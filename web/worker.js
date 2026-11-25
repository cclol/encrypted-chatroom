import init, { start_worker } from "./pkg/web_client.js";

async function bootstrap() {
  if (typeof WebAssembly !== "object" || typeof WebAssembly.instantiate !== "function") {
    self.postMessage(
      JSON.stringify({
        type: "error",
        code: "wasm_unavailable",
        message: "WebAssembly is disabled or unavailable in this browser.",
      }),
    );
    return;
  }
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
