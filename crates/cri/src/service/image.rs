// SPDX-License-Identifier: Apache-2.0
//! `runtime.v1.ImageService`.

use super::convert::*;
use super::{once, status, Cri, Stream};
use crate::api::*;
use crate::engine::{found, Engine};
use tonic::{Request, Response, Status};

impl<E: Engine> Cri<E> {
    /// The engine resolves the name (short names, IDs, digests).
    async fn find_image(
        &self,
        want: &str,
    ) -> Result<Option<velarx_proto::workload::ImageRecord>, Status> {
        if want.is_empty() {
            return Err(Status::invalid_argument("no image"));
        }
        found(self.engine.image_inspect(want).await).map_err(status)
    }

    /// The image of the infra containers: the one the CRI makes sandboxes
    /// with, else the engine's (asked once: `RuntimeInspect` is the whole
    /// system record, and the kubelet asks for the status of an image at
    /// each container it makes).
    async fn infra_image(&self) -> Result<String, Status> {
        if !self.sandbox_image.is_empty() {
            return Ok(self.sandbox_image.clone());
        }
        self.engine_infra_image
            .get_or_try_init(|| async {
                self.engine
                    .version()
                    .await
                    .map(|v| v.infra_image)
                    .map_err(status)
            })
            .await
            .cloned()
    }

    async fn list_images_of(&self, filter: Option<&ImageFilter>) -> Result<Vec<Image>, Status> {
        let infra = self.infra_image().await?;
        let want = filter
            .and_then(|f| f.image.as_ref())
            .map(|s| s.image.as_str())
            .filter(|s| !s.is_empty());
        if let Some(w) = want {
            return Ok(self
                .find_image(w)
                .await?
                .iter()
                .map(|i| image_of(i, &infra))
                .collect());
        }
        let all = self.engine.image_list().await.map_err(status)?;
        Ok(all.iter().map(|i| image_of(i, &infra)).collect())
    }
}

#[tonic::async_trait]
impl<E: Engine> image_service_server::ImageService for Cri<E> {
    type StreamImagesStream = Stream<StreamImagesResponse>;

    async fn list_images(
        &self,
        req: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let images = self.list_images_of(req.get_ref().filter.as_ref()).await?;
        Ok(Response::new(ListImagesResponse { images }))
    }

    async fn stream_images(
        &self,
        req: Request<StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        let images = self.list_images_of(req.get_ref().filter.as_ref()).await?;
        Ok(Response::new(once(StreamImagesResponse { images })))
    }

    async fn image_status(
        &self,
        req: Request<ImageStatusRequest>,
    ) -> Result<Response<ImageStatusResponse>, Status> {
        let spec = req.get_ref().image.clone().unwrap_or_default();
        let want = if spec.image.is_empty() {
            &spec.image_ref
        } else {
            &spec.image
        };
        let Some(found) = self.find_image(want).await? else {
            return Ok(Response::new(ImageStatusResponse::default()));
        };
        let infra = self.infra_image().await?;
        let mut info = std::collections::HashMap::new();
        if req.get_ref().verbose {
            info.insert(
                "info".to_string(),
                serde_json::json!({"id": found.id, "size": found.size, "user": found.config.user})
                    .to_string(),
            );
        }
        Ok(Response::new(ImageStatusResponse {
            image: Some(image_of(&found, &infra)),
            info,
        }))
    }

    async fn pull_image(
        &self,
        req: Request<PullImageRequest>,
    ) -> Result<Response<PullImageResponse>, Status> {
        let r = req.get_ref();
        let spec = r.image.clone().unwrap_or_default();
        if !spec.runtime_handler.is_empty() {
            return Err(Status::unimplemented(
                "velarx: PullImage: the images of the runtime handlers are not separate: the image store is the engine's",
            ));
        }
        let reference = if spec.user_specified_image.is_empty() {
            spec.image
        } else {
            spec.user_specified_image
        };
        if reference.is_empty() {
            return Err(Status::invalid_argument("no image to pull"));
        }
        let access = r.auth.as_ref().map(auth_of).transpose()?.flatten();
        let id = self
            .engine
            .image_pull(&reference, access.as_ref())
            .await
            .map_err(status)?;
        Ok(Response::new(PullImageResponse { image_ref: id }))
    }

    async fn remove_image(
        &self,
        req: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let spec = req.get_ref().image.clone().unwrap_or_default();
        let want = if spec.image.is_empty() {
            &spec.image_ref
        } else {
            &spec.image
        };
        if let Some(i) = self.find_image(want).await? {
            // (an image that a call at the same time removed is gone: done)
            found(self.engine.image_remove(&i.id).await).map_err(status)?;
        }
        Ok(Response::new(RemoveImageResponse {}))
    }

    async fn image_fs_info(
        &self,
        _req: Request<ImageFsInfoRequest>,
    ) -> Result<Response<ImageFsInfoResponse>, Status> {
        let u = self.engine.store_usage().await.map_err(status)?;
        let usage = |bytes: u64| FilesystemUsage {
            timestamp: now_ns(),
            fs_id: Some(FilesystemIdentifier {
                mountpoint: u.mountpoint.clone(),
            }),
            used_bytes: u64v(bytes),
            inodes_used: u.inodes_used.and_then(u64v),
        };
        Ok(Response::new(ImageFsInfoResponse {
            image_filesystems: vec![usage(u.images_bytes)],
            container_filesystems: vec![usage(u.containers_bytes)],
        }))
    }
}
