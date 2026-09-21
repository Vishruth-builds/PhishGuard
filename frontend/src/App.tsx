import { useState } from "react";

type Indicator = {
  name: string;
  status: "good" | "warning" | "danger";
  message: string;
};

type AnalysisResult = {
  url: string;
  score: number;
  verdict: string;
  level: "good" | "warning" | "danger";
  hostname: string;
  domain: string;
  ml_probability: number | null;
  indicators: Indicator[];
};

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyzeURL() {
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }),
      });

      const data = await response.json();

      if (data.error) {
        throw new Error(data.error);
      }

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  function getScoreColor() {
    if (!result) return "text-white";
    if (result.score >= 60) return "text-red-400";
    if (result.score >= 30) return "text-yellow-400";
    return "text-green-400";
  }

  function getBarColor(value: number) {
    if (value >= 60) return "bg-red-400";
    if (value >= 30) return "bg-yellow-400";
    return "bg-green-400";
  }

  function getStatusIcon(status: string) {
    if (status === "danger") return "✕";
    if (status === "warning") return "⚠";
    return "✓";
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* NAVBAR */}
      <nav className="border-b border-slate-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-xl">
              🛡️
            </div>
            <span className="text-xl font-bold">PhishGuard</span>
          </div>
          <span className="text-sm text-slate-500">URL Threat Analyzer</span>
        </div>
      </nav>

      {/* MAIN */}
      <main className="mx-auto max-w-6xl px-6 py-16">
        {/* HERO */}
        <div className="mx-auto max-w-3xl text-center">
          <div className="mb-6 inline-flex rounded-full border border-cyan-500/20 bg-cyan-500/5 px-4 py-2 text-sm text-cyan-300">
            🔐 Cybersecurity URL Analysis
          </div>

          <h1 className="text-5xl font-black tracking-tight md:text-6xl">
            Is this URL <span className="text-cyan-400">safe?</span>
          </h1>

          <p className="mt-6 text-lg leading-8 text-slate-400">
            Analyze a URL using multiple security indicators and receive an
            explainable risk assessment.
          </p>

          {/* URL INPUT */}
          <div className="mt-10 rounded-2xl border border-slate-800 bg-slate-900 p-3">
            <div className="flex flex-col gap-3 md:flex-row">
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") analyzeURL();
                }}
                placeholder="https://example.com/login"
                className="flex-1 rounded-xl bg-slate-950 px-5 py-4 text-white outline-none ring-1 ring-slate-800 focus:ring-2 focus:ring-cyan-500"
              />
              <button
                onClick={analyzeURL}
                disabled={loading}
                className="rounded-xl bg-cyan-400 px-7 py-4 font-bold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-50"
              >
                {loading ? "Analyzing..." : "Analyze URL"}
              </button>
            </div>
          </div>

          {error && (
            <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-red-300">
              {error}
            </div>
          )}
        </div>

        {/* RESULTS */}
        {result && (
          <section className="mt-14">
            <div className="grid gap-6 lg:grid-cols-3">
              {/* RISK SCORE */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-8 text-center">
                <p className="text-sm uppercase tracking-widest text-slate-500">
                  Risk Score
                </p>

                <div className={`mt-6 text-7xl font-black ${getScoreColor()}`}>
                  {result.score}
                </div>
                <p className="mt-2 text-slate-500">/ 100</p>

                {/* RISK SCORE BAR */}
                <div className="mt-6 h-3 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${getBarColor(
                      result.score
                    )}`}
                    style={{ width: `${result.score}%` }}
                  />
                </div>

                <div
                  className={`mx-auto mt-6 inline-flex rounded-full px-4 py-2 text-sm font-bold ${
                    result.level === "danger"
                      ? "bg-red-500/10 text-red-400"
                      : result.level === "warning"
                      ? "bg-yellow-500/10 text-yellow-400"
                      : "bg-green-500/10 text-green-400"
                  }`}
                >
                  {result.verdict}
                </div>

                {/* ML CONFIDENCE BAR */}
                {result.ml_probability !== null && (
                  <div className="mt-8 text-left">
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>ML Model Confidence</span>
                      <span>{result.ml_probability}% phishing</span>
                    </div>
                    <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${getBarColor(
                          result.ml_probability
                        )}`}
                        style={{ width: `${result.ml_probability}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* URL INFORMATION */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-8 lg:col-span-2">
                <p className="text-sm uppercase tracking-widest text-slate-500">
                  Analyzed URL
                </p>

                <div className="mt-4 break-all rounded-xl bg-slate-950 p-4 font-mono text-sm text-cyan-300">
                  {result.url}
                </div>

                <div className="mt-6 grid gap-6 sm:grid-cols-2">
                  <div>
                    <p className="text-sm text-slate-500">Hostname</p>
                    <p className="mt-1 break-all font-medium">{result.hostname}</p>
                  </div>

                  <div>
                    <p className="text-sm text-slate-500">Registered Domain</p>
                    <p className="mt-1 font-medium">{result.domain || "Unknown"}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* SECURITY INDICATORS */}
            <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900 p-8">
              <h2 className="text-xl font-bold">Security Indicators</h2>
              <p className="mt-1 text-sm text-slate-500">
                Factors used in the risk assessment
              </p>

              <div className="mt-6 grid gap-3 md:grid-cols-2">
                {result.indicators.map((indicator, index) => (
                  <div
                    key={index}
                    className="flex gap-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                  >
                    <div
                      className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg font-bold ${
                        indicator.status === "danger"
                          ? "bg-red-500/10 text-red-400"
                          : indicator.status === "warning"
                          ? "bg-yellow-500/10 text-yellow-400"
                          : "bg-green-500/10 text-green-400"
                      }`}
                    >
                      {getStatusIcon(indicator.status)}
                    </div>

                    <div>
                      <p className="font-semibold">{indicator.name}</p>
                      <p className="mt-1 text-sm leading-6 text-slate-500">
                        {indicator.message}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* DISCLAIMER */}
            <div className="mt-6 rounded-xl border border-slate-800 bg-slate-900/50 p-5 text-sm leading-6 text-slate-500">
              <strong className="text-slate-300">Important:</strong>{" "}
              This is an automated heuristic assessment. A low score does not
              guarantee that a website is safe, and a high score does not by
              itself prove that a website is malicious.
            </div>
          </section>
        )}
      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-800 py-8 text-center text-sm text-slate-600">
        PhishGuard • Cybersecurity Learning Project
      </footer>
    </div>
  );
}

export default App;