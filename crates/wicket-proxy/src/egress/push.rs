//! A git push as one request (#26): reading a receive-pack body's ref update commands, and refusing
//! a push to a protected ref before it is decided. Part of [`super::Egress`].

use super::*;

impl Egress {
    /// Why a push to ref `name` of `repo` on `host` is refused, if it is: a name git wouldn't accept,
    /// a ref the forge never accepts a push to, or one a forbid rule protects (its ref paths, as
    /// the zone, the org policy or the box's token decide them; see `wicket_core::git`).
    pub(super) fn refuses_ref(&self, host: &str, repo: &str, name: &str) -> Option<String> {
        if let Some(why) = wicket_core::git::bad_ref_name(name).or_else(|| wicket_core::git::forge_refuses(host, name)) {
            return Some(format!("a push to {name}: {why}"));
        }
        let ctx = &self.ctx;
        wicket_core::git::ref_paths(repo, name).iter().find_map(|p| {
            let op = Op::egress(&ctx.tenant, &ctx.run, &ctx.zone.name, "POST", host, p);
            self.decider.refuses(ctx, &op).map(|why| format!("a push to protected ref {name}: {why}"))
        })
    }
}

/// A request body whose start has been read, then the rest as it arrives.
pub(super) type ReadBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Reads a receive-pack body up to the end of its ref update commands (`wicket_core::git::commands`),
/// and gives back the commands and the whole body: what was read, then the rest, unread.
pub(super) async fn read_commands<B>(body: B) -> std::result::Result<(Vec<wicket_core::git::RefUpdate>, ReadBody), String>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut body = Box::pin(body);
    let mut buf = Vec::new();
    let updates = loop {
        if let Some(c) = wicket_core::git::commands(&buf)? {
            break c;
        }
        match body.frame().await {
            None => return Err("the body ended before its commands did".into()),
            Some(Err(e)) => return Err(format!("request body: {}", e.into())),
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data() {
                    buf.extend_from_slice(&d);
                }
            }
        }
    };
    use futures_util::StreamExt;
    let head = futures_util::stream::once(std::future::ready(Ok(Frame::data(Bytes::from(buf)))));
    let rest = TryStreamExt::map_err(http_body_util::BodyStream::new(body), |e| -> Box<dyn std::error::Error + Send + Sync> { e.into() });
    Ok((updates, StreamBody::new(head.chain(rest)).boxed_unsync()))
}
