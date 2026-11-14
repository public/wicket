//! `wicket image` and `doctor`: the agent image and the host's readiness.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Image { cmd: Some(ImageCmd::Digest { refs }), .. } => {
            let d = wicket_sandbox::Docker::from_env();
            for r in &refs {
                wicket_core::image::parse(r).map_err(anyhow::Error::msg)?;
                let i = d.image_identity(r).await?.with_context(|| format!("no image {r} here"))?;
                println!("{r} {}", i.id);
            }
            Ok(())
        }
        Cmd::Image { tag, dir, .. } => {
            // An installed version (a control host, or a node after `wicket node install`) builds its own
            // image, `wicket/claude-code:<build id>`, by default: the one its boxes, and the control
            // host's runs placed on it, ask for. An explicit --tag is kept as given (#277).
            let own = image::effective(image::DEFAULT);
            let tag = image::build_tag(tag, &own);
            let ctx = match &dir {
                Some(d) => image::context(d)?,
                None => image::embedded_context()?,
            };
            // A derived image (examples/self-hosting) builds on this installation's own (#277).
            let df = std::fs::read_to_string(ctx.dir.join("Dockerfile")).unwrap_or_default();
            let args: Vec<(&str, &str)> = if image::declares_arg(&df, "BASE") { vec![("BASE", own.as_str())] } else { vec![] };
            let d = wicket_sandbox::Docker::from_env();
            d.build_image(&tag, &ctx.dir, &args).await?;
            // Its digest: what a zone pins it as (#192).
            match d.image_identity(&tag).await? {
                Some(i) => println!("built {tag} ({}; pin it as {})", i.id, wicket_core::image::pinned(&tag, &i.id)),
                None => println!("built {tag}"),
            }
            Ok(())
        }
        Cmd::Doctor { image } => doctor::doctor(&image).await,
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum ImageCmd {
    /// The digest each image is in this installation's Docker (#192): `<ref> sha256:…`, what a zone
    /// pins it as (`name@sha256:…`).
    Digest {
        #[arg(required = true)]
        refs: Vec<String>,
    },
}
