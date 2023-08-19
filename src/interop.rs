#[cfg(not(target_arch = "wasm32"))]
pub async fn universal_sleep(duration_ms: u32) {
    use tokio::time::{sleep, Duration};

    sleep(Duration::from_millis(duration_ms.into())).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn universal_sleep(duration_ms: u32) {
    gloo_timers::future::TimeoutFuture::new(duration_ms).await;
}
