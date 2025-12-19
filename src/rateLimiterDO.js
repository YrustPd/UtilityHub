export class RateLimiterDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    let payload;
    try {
      payload = await request.json();
    } catch (error) {
      return new Response(JSON.stringify({ error: 'invalid_body' }), { status: 400 });
    }

    const key = payload?.key;
    const windowSec = Number(payload?.windowSec) || 60;
    const limit = Number(payload?.limit) || 60;

    if (!key || !Number.isFinite(windowSec) || !Number.isFinite(limit)) {
      return new Response(JSON.stringify({ error: 'invalid_payload' }), { status: 400 });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const bucket = Math.floor(nowSec / windowSec);
    const stored = (await this.state.storage.get(key)) || { bucket: null, count: 0 };

    const count = stored.bucket === bucket ? stored.count : 0;
    const allowed = count < limit;
    const nextCount = allowed ? count + 1 : count;

    await this.state.storage.put(key, { bucket, count: nextCount });

    const resetEpoch = (bucket + 1) * windowSec;
    const remaining = Math.max(0, limit - nextCount);

    return new Response(
      JSON.stringify({ allowed, remaining, resetEpoch, limit }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
