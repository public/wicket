//! The control/node channel (#219): its protocol ([`chan`]), and the modules its messages carry, a
//! node's health ([`health`]), the secrets a node holds for its boxes ([`nodesecrets`]), and OCI
//! images and the registries a node pulls them from ([`oci`], [`registry`]).
//!
//! A library split from wicket-cli so it builds and tests on its own, and so the fuzz targets use it
//! as it is (`fuzz/`): it depends on no module of the CLI's.

pub mod chan;
pub mod health;
pub mod nodesecrets;
pub mod oci;
pub mod registry;

/// Whether `id` is a run id wicket made (`run_` and 26 lowercase letters or digits).
pub fn check_run_id(id: &str) -> anyhow::Result<()> {
    if id.len() == 30 && id.starts_with("run_") && id[4..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        Ok(())
    } else {
        anyhow::bail!("bad run id {id:?}")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_run_id_is_run_and_26_lowercase_letters_or_digits() {
        assert!(super::check_run_id("run_0123456789abcdefghijklmnop").is_ok());
        for bad in [
            "",
            "run_",
            "run_0123456789ABCDEFGHIJKLMNOP",
            "job_0123456789abcdefghijklmnop",
            "run_0123456789abcdefghijklmnop0",
            "run_../../../etc/passwdxxxxxxxx",
        ] {
            assert!(super::check_run_id(bad).is_err(), "{bad}");
        }
    }
}
