# Integrating zk-ai

## zk-drive (Web)

```bash
cd /Users/Ken/workspaces/zk-drive/frontend
npm install @zk-ai/web
```

```tsx
import { useSummarize } from '@zk-ai/web/hooks';

function DocumentSummary({ text }: { text: string }) {
  const { summarize, result, loading, error } = useSummarize();

  return (
    <div>
      <button onClick={() => summarize(text, 'vi')} disabled={loading}>
        {loading ? 'Summarizing...' : 'Summarize'}
      </button>
      {error && <p className="text-red-500">{error}</p>}
      {result && <p>{result.output}</p>}
    </div>
  );
}
```

## zk-drive (Desktop — Electron + Tauri)

```bash
cd /Users/Ken/workspaces/zk-drive/desktop
npm install @zk-ai/napi
```

```ts
// In Electron main process
import { ZkAiEngine } from '@zk-ai/napi';

const engine = new ZkAiEngine(app.getPath('userData') + '/zk-ai-models');
const profile = engine.profile();
console.log(`Device tier: ${profile.tier}, acceleration: ${profile.acceleration}`);

// In renderer via contextBridge
const result = await engine.summarize(documentText, 'vi');
```

## zk-drive (Mobile — iOS)

1. Build the UniFFI static library:
```bash
cd /Users/Ken/workspaces/zk-ai
./scripts/build-ios.sh
```

2. Add the XCFramework to your Xcode project

3. Use in Swift:
```swift
import zk_ai_uniffi

let engine = try ZkAiEngine(cacheDir: "zk-ai-models")
let profile = engine.profile()
print("Device tier: \(profile.tier)")

let result = try await engine.summarize(text: documentText, language: "vi")
print(result.output)
```

## zk-drive (Mobile — Android)

1. Build the UniFFI shared library:
```bash
cd /Users/Ken/workspaces/zk-ai
./scripts/build-android.sh
```

2. Copy `.so` files to `app/src/main/jniLibs/`

3. Use in Kotlin:
```kotlin
import uniffi.zk_ai_uniffi.*

val engine = ZkAiEngine("zk-ai-models")
val profile = engine.profile()
println("Device tier: ${profile.tier}")

val result = engine.summarize(documentText, "vi")
println(result.output)
```

## zk-drive (Server offload)

```bash
# Build the Rust static library
cd /Users/Ken/workspaces/zk-ai
./scripts/build-go-ffi.sh

# Build and run the Go server
cd server
CGO_ENABLED=1 go build -o zk-ai-server ./cmd/zk-ai-server
./zk-ai-server --addr :8090 --cache-dir /tmp/zk-ai-models
```

## KChat (Swarm inference)

Implement the `SwarmTransport` trait over KChat's existing XMPP/MLS layer:

```rust
use zk_ai_core::swarm::{SwarmTransport, SwarmCoordinator, DeviceCapability};

struct KChatTransport {
    // KChat's existing XMPP client + MLS group session
}

#[async_trait]
impl SwarmTransport for KChatTransport {
    async fn broadcast_capability(&self, cap: &DeviceCapability) -> Result<()> {
        // Send via XMPP message to the group (MLS-encrypted)
    }
    // ... other methods
}
```
