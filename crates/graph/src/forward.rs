// SPDX-License-Identifier: Apache-2.0
//! The forwarding half of a wrapper driver: [`forward_storage_driver!`] writes
//! the `StorageDriver` methods that call the wrapped driver unchanged, so a
//! wrapper (one that watches `collect`, changes the capabilities, fakes the
//! image volumes) states only the methods it changes.  A new trait method is
//! added to the trait and to one arm of the macro, not to every wrapper.

/// The types the signatures of [`forward_storage_driver!`] name.
#[doc(hidden)]
pub mod types {
    pub use crate::*;
    pub use async_trait::async_trait;
    pub use velarx_content::layer::dirtar::Change;
    pub use velarx_content::layer::holes::HoleWrite;
    pub use velarx_db::{ImageRecord, LayerKey, LayerRecord};
    pub use velarx_fuse::view::ImageTree;
    pub use velarx_storage::{ObjectOpener, Toc};
}

/// `impl StorageDriver for T` with the methods named in `forward` calling
/// `self.<field>` (a wrapped `Arc<dyn StorageDriver>`) unchanged; the other
/// methods are the items after them.
///
/// ```ignore
/// forward_storage_driver! {
///     impl StorageDriver for Watching {
///         inner: inner;
///         forward: [name graph_name status pull];
///         fn capabilities(&self) -> &Capabilities { &self.caps }
///     }
/// }
/// ```
#[macro_export]
macro_rules! forward_storage_driver {
    (impl StorageDriver for $ty:ty {
        inner: $f:ident;
        forward: [$($m:ident)*];
        $($ov:item)*
    }) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($ov)*], [$($m)*]);
    };

    (@go $ty:ty, $f:ident, [$($acc:tt)*], []) => {
        #[$crate::forward::types::async_trait]
        impl $crate::StorageDriver for $ty {
            $($acc)*
        }
    };
    (@go $ty:ty, $f:ident, [$($acc:tt)*], [$m:ident $($rest:ident)*]) => {
        $crate::forward_storage_driver!(@one $f $m; $ty; [$($acc)*]; [$($rest)*]);
    };

    (@one $f:ident name; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn name(&self) -> &str { self.$f.name() }], [$($rest)*]);
    };
    (@one $f:ident graph_name; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn graph_name(&self) -> &str { self.$f.graph_name() }], [$($rest)*]);
    };
    (@one $f:ident capabilities; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn capabilities(&self) -> &$crate::forward::types::Capabilities {
            self.$f.capabilities()
        }], [$($rest)*]);
    };
    (@one $f:ident graph_data; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn graph_data(&self, w: &$crate::forward::types::Writable) -> Vec<(String, String)> {
            self.$f.graph_data(w)
        }], [$($rest)*]);
    };
    (@one $f:ident status; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn status(&self) -> Vec<(String, String)> { self.$f.status() }], [$($rest)*]);
    };
    (@one $f:ident pull; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn pull(
            &self,
            feed: &::std::sync::Arc<dyn $crate::forward::types::PullFeed>,
            layers: &[$crate::forward::types::FeedLayer],
            settled: $crate::forward::types::Settled,
        ) -> $crate::DriverResult<$crate::forward::types::Pulled> {
            self.$f.pull(feed, layers, settled).await
        }], [$($rest)*]);
    };
    (@one $f:ident has_layers; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn has_layers(
            &self,
            layers: &[$crate::forward::types::LayerRef],
        ) -> $crate::DriverResult<Vec<bool>> {
            self.$f.has_layers(layers).await
        }], [$($rest)*]);
    };
    (@one $f:ident repair; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn repair(
            &self,
            layers: &[$crate::forward::types::LayerRef],
        ) -> $crate::DriverResult<
            ::std::collections::HashMap<
                $crate::forward::types::LayerKey,
                $crate::forward::types::LayerArtifact,
            >,
        > {
            self.$f.repair(layers).await
        }], [$($rest)*]);
    };
    (@one $f:ident remake_staged; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn remake_staged(&self, id: &str) -> $crate::DriverResult<()> {
            self.$f.remake_staged(id).await
        }], [$($rest)*]);
    };
    (@one $f:ident read_objects; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn read_objects(
            &self,
            ranges: &[$crate::forward::types::ObjectRange],
            sink: &mut dyn $crate::forward::types::ObjectSink,
        ) -> $crate::DriverResult<()> {
            self.$f.read_objects(ranges, sink)
        }], [$($rest)*]);
    };
    (@one $f:ident open_object; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn open_object(&self, key: &str, size: u64) -> $crate::DriverResult<::std::fs::File> {
            self.$f.open_object(key, size)
        }], [$($rest)*]);
    };
    (@one $f:ident objects_in_order; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn objects_in_order(
            &self,
            order: &mut dyn FnMut() -> Vec<(String, u64)>,
        ) -> Option<::std::sync::Arc<dyn $crate::forward::types::ObjectOpener>> {
            self.$f.objects_in_order(order)
        }], [$($rest)*]);
    };
    (@one $f:ident remove_image; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn remove_image(&self, image_id: &str) -> $crate::DriverResult<()> {
            self.$f.remove_image(image_id)
        }], [$($rest)*]);
    };
    (@one $f:ident image_volume_create; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn image_volume_create(
            &self,
            req: &$crate::forward::types::MountRequest<'_>,
        ) -> $crate::DriverResult<$crate::forward::types::Planned> {
            self.$f.image_volume_create(req)
        }], [$($rest)*]);
    };
    (@one $f:ident mounts; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn mounts(
            &self,
            req: &$crate::forward::types::MountsRequest<'_>,
        ) -> $crate::DriverResult<$crate::forward::types::Mounts> {
            self.$f.mounts(req)
        }], [$($rest)*]);
    };
    (@one $f:ident image_view; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn image_view(
            &self,
            image_id: &str,
            layers: &[$crate::forward::types::LayerRecord],
        ) -> $crate::DriverResult<::std::sync::Arc<dyn $crate::forward::types::ImageTree>> {
            self.$f.image_view(image_id, layers)
        }], [$($rest)*]);
    };
    (@one $f:ident leftovers; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn leftovers(
            &self,
            grace: ::std::time::Duration,
        ) -> $crate::DriverResult<Vec<(::std::path::PathBuf, String)>> {
            self.$f.leftovers(grace).await
        }], [$($rest)*]);
    };
    (@one $f:ident check; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn check(
            &self,
            image: &$crate::forward::types::ImageRecord,
            layers: &[$crate::forward::types::LayerRecord],
            full: bool,
        ) -> $crate::DriverResult<Vec<$crate::forward::types::Problem>> {
            self.$f.check(image, layers, full).await
        }], [$($rest)*]);
    };
    (@one $f:ident collect; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn collect(
            &self,
            keep: &$crate::forward::types::Keep,
        ) -> $crate::DriverResult<$crate::forward::types::Collected> {
            self.$f.collect(keep)
        }], [$($rest)*]);
    };
    (@one $f:ident release_engine_copies; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* async fn release_engine_copies(
            &self,
            layers: &[$crate::forward::types::LayerKey],
            held: &$crate::forward::types::EngineHeld,
        ) -> $crate::DriverResult<$crate::forward::types::Collected> {
            self.$f.release_engine_copies(layers, held).await
        }], [$($rest)*]);
    };
    (@one $f:ident lock_unused_layers; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn lock_unused_layers(
            &self,
            layers: &[$crate::forward::types::LayerKey],
        ) -> $crate::DriverResult<$crate::forward::types::UnusedLayers> {
            self.$f.lock_unused_layers(layers)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_create; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_create(
            &self,
            w: &$crate::forward::types::Writable,
            owner: Option<(u32, u32)>,
            opts: &$crate::forward::types::WritableOptions,
            base: Option<&$crate::forward::types::MountRequest<'_>>,
        ) -> $crate::DriverResult<Option<$crate::forward::types::Planned>> {
            self.$f.writable_create(w, owner, opts, base)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_paths; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_paths(
            &self,
            w: &$crate::forward::types::Writable,
        ) -> $crate::forward::types::WritablePaths {
            self.$f.writable_paths(w)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_root; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_root(
            &self,
            w: &$crate::forward::types::Writable,
        ) -> $crate::DriverResult<::std::os::fd::OwnedFd> {
            self.$f.writable_root(w)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_size; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_size(&self, w: &$crate::forward::types::Writable) -> $crate::DriverResult<u64> {
            self.$f.writable_size(w)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_remove; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_remove(&self, w: &$crate::forward::types::Writable) -> $crate::DriverResult<()> {
            self.$f.writable_remove(w)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_release; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_release(&self, w: &$crate::forward::types::Writable) -> $crate::WritableRelease {
            self.$f.writable_release(w)
        }], [$($rest)*]);
    };
    (@one $f:ident writable_exists; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn writable_exists(&self, w: &$crate::forward::types::Writable) -> $crate::DriverResult<bool> {
            self.$f.writable_exists(w)
        }], [$($rest)*]);
    };
    (@one $f:ident diff; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn diff(
            &self,
            w: &$crate::forward::types::Writable,
            lower: Option<::std::sync::Arc<dyn $crate::forward::types::ImageTree>>,
            opts: &$crate::forward::types::DiffOptions,
            out: &mut dyn $crate::forward::types::HoleWrite,
        ) -> $crate::DriverResult<()> {
            self.$f.diff(w, lower, opts, out)
        }], [$($rest)*]);
    };
    (@one $f:ident changes; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn changes(
            &self,
            w: &$crate::forward::types::Writable,
            lower: Option<::std::sync::Arc<dyn $crate::forward::types::ImageTree>>,
            opts: &$crate::forward::types::DiffOptions,
        ) -> $crate::DriverResult<Vec<(String, $crate::forward::types::Change)>> {
            self.$f.changes(w, lower, opts)
        }], [$($rest)*]);
    };
    (@one $f:ident apply; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn apply(
            &self,
            w: &$crate::forward::types::Writable,
            opts: &$crate::forward::types::DiffOptions,
            tar: &mut dyn ::std::io::Read,
        ) -> $crate::DriverResult<()> {
            self.$f.apply(w, opts, tar)
        }], [$($rest)*]);
    };
    (@one $f:ident stopped_view; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn stopped_view<'a>(
            &self,
            w: &$crate::forward::types::Writable,
            image: $crate::forward::types::TreeSource<'a>,
        ) -> $crate::DriverResult<$crate::forward::types::StoppedView<'a>> {
            self.$f.stopped_view(w, image)
        }], [$($rest)*]);
    };
    (@one $f:ident holds_objects; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn holds_objects(&self) -> bool { self.$f.holds_objects() }], [$($rest)*]);
    };
    (@one $f:ident is_root_of; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn is_root_of(
            &self,
            w: &$crate::forward::types::Writable,
            proc_dir: &::std::path::Path,
        ) -> $crate::DriverResult<bool> {
            self.$f.is_root_of(w, proc_dir)
        }], [$($rest)*]);
    };
    (@one $f:ident usage; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn usage(&self) -> $crate::DriverResult<$crate::forward::types::Usage> {
            self.$f.usage()
        }], [$($rest)*]);
    };
    (@one $f:ident list_stores; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn list_stores(&self) -> $crate::DriverResult<Vec<$crate::forward::types::StoreInfo>> {
            self.$f.list_stores()
        }], [$($rest)*]);
    };
    (@one $f:ident drop_store; $ty:ty; [$($acc:tt)*]; [$($rest:ident)*]) => {
        $crate::forward_storage_driver!(@go $ty, $f, [$($acc)* fn drop_store(&self, store: &str) -> $crate::DriverResult<()> {
            self.$f.drop_store(store)
        }], [$($rest)*]);
    };
}

#[cfg(test)]
mod tests {
    use super::types::*;
    use std::sync::Arc;

    /// Every method of the trait is forwarded: the macro names them all
    /// (a method the macro lacks is a compile error here), and a method that
    /// is overridden is the override.
    struct Wrap {
        inner: Arc<dyn StorageDriver>,
        caps: Capabilities,
    }

    crate::forward_storage_driver! {
        impl StorageDriver for Wrap {
            inner: inner;
            forward: [
                name graph_name graph_data status pull  has_layers
                repair remake_staged read_objects open_object objects_in_order remove_image
                image_volume_create mounts image_view holds_objects
                leftovers check collect writable_create writable_paths writable_root writable_size
                writable_remove writable_release writable_exists diff changes apply stopped_view
                is_root_of usage list_stores drop_store release_engine_copies lock_unused_layers
            ];
            fn capabilities(&self) -> &Capabilities {
                &self.caps
            }
        }
    }

    #[test]
    fn the_macro_covers_the_trait() {
        fn is_driver<T: StorageDriver>() {}
        is_driver::<Wrap>();
    }

    /// Every wrapper names each method of the trait once: in `forward` or
    /// as a method of its own.  A method with a default body (`open_object`,
    /// `image_volume_create`, `holds_objects`,
    /// `list_stores`, `drop_store`) that a wrapper
    /// left out would compile and run the default, not the wrapped driver's.
    #[test]
    fn every_wrapper_forwards_or_states_every_method() {
        let source = include_str!("lib.rs");
        let trait_text = &source[source.find("pub trait StorageDriver").unwrap()..];
        let trait_text = &trait_text[..trait_text.find("\n}\n").unwrap()];
        let methods: Vec<&str> = trait_text
            .lines()
            .filter_map(|l| {
                let l = l.strip_prefix("    ")?;
                let l = l.strip_prefix("async ").unwrap_or(l);
                let name = l.strip_prefix("fn ")?;
                Some(&name[..name.find(['(', '<'])?])
            })
            .collect();
        assert!(methods.len() > 25, "{methods:?}");
        for (ty, file) in [
            ("Chained", include_str!("conformance.rs")),
            ("VolumeFake", include_str!("conformance/volumes.rs")),
            (
                "Watching",
                include_str!("../../core/src/storage_driver/watching.rs"),
            ),
            (
                "LazyPhase",
                include_str!("../../core/src/storage_driver/lazy_phase.rs"),
            ),
            ("Wrap", include_str!("forward.rs")),
        ] {
            let body = &file[file
                .find(&format!("impl StorageDriver for {ty} {{"))
                .unwrap()..];
            let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
            let list = &body[body.find("forward: [").unwrap() + "forward: [".len()..];
            let forwarded: Vec<&str> = list[..list.find(']').unwrap()].split_whitespace().collect();
            for m in &methods {
                let own = body.contains(&format!("fn {m}(")) || body.contains(&format!("fn {m}<"));
                assert!(
                    forwarded.contains(m) != own,
                    "{ty}: `{m}` must be forwarded or stated, not both nor neither"
                );
            }
        }
    }
}
