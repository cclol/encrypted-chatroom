import init, { start_worker } from "./pkg/web_client.js";

async function bootstrap() {
  try {
    await init();
    start_worker();
  } catch (err) {
    self.postMessage(
      JSON.stringify({
        type: "error",
        code: "wasm_boot_failed",
        message: "Failed to start WASM worker: " + String(err),
      }),
    );
  }
}

bootstrap();
