// SPDX-License-Identifier: Apache-2.0
/// The vendor, class and name of a CDI device (`vendor.com/class=name`),
/// split as the CDI library does; none for anything else.  Whether the
/// parts are valid is for the engine to say.
pub fn split_cdi_device(device: &str) -> Option<(&str, &str, &str)> {
    if device.starts_with('/') {
        return None;
    }
    let (qualifier, name) = device.split_once('=')?;
    let (vendor, class) = qualifier.split_once('/')?;
    (!vendor.is_empty() && !class.is_empty() && !name.is_empty()).then_some((vendor, class, name))
}
