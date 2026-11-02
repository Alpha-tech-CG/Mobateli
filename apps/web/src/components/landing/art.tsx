/**
 * Hand-drawn SVG/CSS illustrations for the marketing landing. All original —
 * no third-party images.
 */

const LINE = "#3a3e41";

/** Dark metallic shield with a green check (hero focal visual). */
export function HeroShield({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 240 280" className={className} aria-hidden>
      <defs>
        <linearGradient id="sh-outer" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#5a5e61" />
          <stop offset=".45" stopColor="#1b1d1f" />
          <stop offset="1" stopColor="#050606" />
        </linearGradient>
        <radialGradient id="sh-inner" cx=".35" cy=".25" r=".9">
          <stop offset="0" stopColor="#6a6e71" />
          <stop offset=".55" stopColor="#36393b" />
          <stop offset="1" stopColor="#1c1e20" />
        </radialGradient>
        <linearGradient id="sh-rim" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#d9dcde" stopOpacity=".9" />
          <stop offset="1" stopColor="#d9dcde" stopOpacity=".05" />
        </linearGradient>
      </defs>
      <path
        d="M120 8C170 30 205 34 228 36V140C228 210 175 255 120 272C65 255 12 210 12 140V36C35 34 70 30 120 8Z"
        fill="url(#sh-outer)"
        stroke="url(#sh-rim)"
        strokeWidth="2"
      />
      <path
        d="M120 34C160 52 188 55 204 57V140C204 196 162 232 120 246C78 232 36 196 36 140V57C52 55 80 52 120 34Z"
        fill="url(#sh-inner)"
        stroke="#0b0c0d"
        strokeWidth="3"
      />
      <path
        d="M86 142L112 168L158 116"
        fill="none"
        stroke="#8ac898"
        strokeWidth="13"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Circuit traces under the hero visual. */
export function Circuit({ className = "" }: { className?: string }) {
  const d = [
    "M0 150 H260 L300 110 H520",
    "M0 70 H170 L210 110 H300",
    "M1200 150 H940 L900 110 H680",
    "M1200 70 H1030 L990 110 H900",
    "M120 200 V150",
    "M1080 200 V150",
  ];
  return (
    <svg viewBox="0 0 1200 200" preserveAspectRatio="none" className={className} aria-hidden>
      {d.map((p) => (
        <path key={p} d={p} fill="none" stroke={LINE} strokeWidth="1.2" />
      ))}
    </svg>
  );
}

/** Isometric cube: white top, brick left face, light right face. */
export function Cube({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 200 220" className={className} aria-hidden>
      <polygon points="100,10 190,60 100,110 10,60" fill="#ffffff" stroke="#d6d9db" />
      <polygon points="10,60 100,110 100,210 10,160" fill="#bb3e2c" />
      <polygon points="100,110 190,60 190,160 100,210" fill="#e7e9eb" stroke="#d6d9db" />
    </svg>
  );
}

/** Three stacked isometric layers (white, white, brick). */
export function IsoStack({ className = "" }: { className?: string }) {
  const layer = (y: number, fill: string, side: string) => (
    <g key={y}>
      <polygon points={`100,${y} 180,${y + 40} 100,${y + 80} 20,${y + 40}`} fill={fill} stroke="#d0d3d6" />
      <polygon points={`20,${y + 40} 100,${y + 80} 100,${y + 92} 20,${y + 52}`} fill={side} />
      <polygon points={`100,${y + 80} 180,${y + 40} 180,${y + 52} 100,${y + 92}`} fill={side} opacity=".85" />
    </g>
  );
  return (
    <svg viewBox="0 0 200 190" className={className} aria-hidden>
      {layer(70, "#bb3e2c", "#8f2f21")}
      {layer(38, "#f1f2f3", "#cfd2d4")}
      {layer(6, "#ffffff", "#dfe1e3")}
    </svg>
  );
}

/** Line chart with point markers (illustrative). */
export function LineChart({ className = "" }: { className?: string }) {
  const pts = [
    [10, 150], [60, 120], [110, 80], [160, 60], [210, 40], [260, 85], [310, 110], [360, 140], [410, 120],
  ];
  return (
    <svg viewBox="0 0 420 180" className={className} aria-hidden>
      {[30, 70, 110, 150].map((y) => (
        <line key={y} x1="0" x2="420" y1={y} y2={y} stroke="#e3e5e7" strokeDasharray="3 4" />
      ))}
      <polyline points={pts.map((p) => p.join(",")).join(" ")} fill="none" stroke="#8ac898" strokeWidth="2" />
      {pts.map(([x, y]) => (
        <circle key={x} cx={x} cy={y} r="5" fill="#fff" stroke="#111" strokeWidth="2" />
      ))}
    </svg>
  );
}

const stroke = { fill: "none", stroke: "#c9ccce", strokeWidth: 1.3 } as const;

function IsoGround() {
  return (
    <>
      <polygon points="150,150 270,210 150,270 30,210" {...stroke} strokeDasharray="4 5" />
      {[[150, 150], [270, 210], [150, 270], [30, 210]].map(([x, y]) => (
        <circle key={`${x}-${y}`} cx={x} cy={y} r="3" fill="#c9ccce" />
      ))}
    </>
  );
}

/** Process step 1 — radar scanning. */
export function IsoRadar({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 300 280" className={className} aria-hidden>
      <IsoGround />
      {[70, 48, 26].map((r) => (
        <ellipse key={r} cx="150" cy="150" rx={r * 1.4} ry={r * 0.8} {...stroke} />
      ))}
      <ellipse cx="150" cy="150" rx="5" ry="3" fill="#eef1f2" />
      <line x1="150" y1="150" x2="228" y2="96" {...stroke} />
      {[[205, 70], [240, 110], [222, 140]].map(([x, y]) => (
        <g key={x} transform={`translate(${x} ${y})`}>
          <polygon points="0,-9 9,-4 0,1 -9,-4" {...stroke} />
          <polygon points="-9,-4 0,1 0,10 -9,5" {...stroke} />
          <polygon points="0,1 9,-4 9,5 0,10" {...stroke} />
        </g>
      ))}
    </svg>
  );
}

/** Process step 2 — anomaly chart window. */
export function IsoChart({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 300 280" className={className} aria-hidden>
      <IsoGround />
      <polygon points="80,40 220,80 220,190 80,150" {...stroke} />
      <line x1="80" y1="58" x2="220" y2="98" {...stroke} />
      <polyline points="95,135 125,120 150,132 175,100 205,118" {...stroke} />
      <polygon points="205,150 240,210 170,210" {...stroke} fill="#191b1c" />
      <line x1="205" y1="170" x2="205" y2="192" {...stroke} />
      <circle cx="205" cy="200" r="1.8" fill="#c9ccce" />
    </svg>
  );
}

/** Process step 3 — shield with check and gear. */
export function IsoShield({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 300 280" className={className} aria-hidden>
      <IsoGround />
      <path d="M170 40C195 52 214 55 228 56V120C228 158 200 182 170 192C140 182 112 158 112 120V56C126 55 145 52 170 40Z" {...stroke} />
      <path d="M150 118L165 133L192 104" {...stroke} strokeWidth={2} />
      <circle cx="98" cy="175" r="22" {...stroke} />
      <circle cx="98" cy="175" r="9" {...stroke} />
      {Array.from({ length: 8 }).map((_, i) => {
        const a = (i * Math.PI) / 4;
        return (
          <line
            key={i}
            x1={98 + Math.cos(a) * 22}
            y1={175 + Math.sin(a) * 22}
            x2={98 + Math.cos(a) * 29}
            y2={175 + Math.sin(a) * 29}
            {...stroke}
            strokeWidth={4}
          />
        );
      })}
    </svg>
  );
}

/** Pixel staircase decoration for card corners. */
export function PixelCorner({ className = "", color = "#ffffff" }: { className?: string; color?: string }) {
  const cells = [
    [3, 0, 1], [2, 0, 0.6], [3, 1, 0.8], [1, 0, 0.3], [2, 1, 0.4], [3, 2, 0.5], [0, 0, 0.15], [1, 1, 0.2], [2, 2, 0.25], [3, 3, 0.3],
  ];
  return (
    <svg viewBox="0 0 40 40" className={className} aria-hidden>
      {cells.map(([x, y, o]) => (
        <rect key={`${x}-${y}`} x={x! * 10} y={y! * 10} width="10" height="10" fill={color} opacity={o} />
      ))}
    </svg>
  );
}

/** Three stacked horizontal bars used between sections. */
export function Bars({ color = "#ffffff", className = "" }: { color?: string; className?: string }) {
  return (
    <div className={`flex flex-col items-center gap-2.5 ${className}`} aria-hidden>
      {["100%", "96%", "90%"].map((w) => (
        <div key={w} className="h-[7px] rounded-full" style={{ width: w, background: color }} />
      ))}
    </div>
  );
}

/** Circuit traces with round pads for the CTA band. */
export function CtaCircuit({ side, className = "" }: { side: "left" | "right"; className?: string }) {
  const flip = side === "right" ? "scale(-1 1) translate(-260 0)" : undefined;
  return (
    <svg viewBox="0 0 260 260" className={className} aria-hidden>
      <g transform={flip} fill="none" stroke="#e8836f" strokeWidth="3">
        <path d="M0 70 H120 L160 40 H200" />
        <path d="M0 130 H230" />
        <path d="M0 190 H120 L160 220 H200" />
      </g>
      <g transform={flip} fill="#e8836f">
        <circle cx="214" cy="40" r="14" />
        <circle cx="244" cy="130" r="14" />
        <circle cx="214" cy="220" r="14" />
      </g>
    </svg>
  );
}

/** "Photo" replacement: a staged scene with a CodeGate terminal. */
export function TerminalScene() {
  const lines: [string, string][] = [
    ["#8ac898", "$ codegate scan --pr 128"],
    ["#9aa3a8", "→ diff: 14 fichiers, 3 dépendances ajoutées"],
    ["#e8836f", "✗ secret: stripe_secret_key  config.ts:3"],
    ["#e0a44a", "! dépendance: react-router-domm (typosquat)"],
    ["#e8836f", "✗ sast: requête SQL concaténée  db.ts:42"],
    ["#eef1f2", "  score de risque ........ 85/100"],
    ["#e8836f", "  décision ................ BLOQUER"],
    ["#8ac898", "✓ issue Linear SEC-212 créée · alerte Slack envoyée"],
  ];
  return (
    <div className="relative mx-auto h-[420px] max-w-[1280px] overflow-hidden sm:h-[560px]">
      <div className="absolute left-[38%] top-[8%] h-[70%] w-[24%] rounded-sm bg-[#f4f4f1] shadow-sm" />
      <div className="absolute left-[56%] top-[30%] h-[52%] w-[22%] rounded-sm bg-[#bb3e2c] shadow-lg" />
      <div className="absolute bottom-[6%] left-[30%] h-[12%] w-[48%] rounded-sm bg-[#f4f4f1]" />
      <div className="absolute left-[8%] top-[22%] w-[46%] min-w-[300px] overflow-hidden rounded-xl border border-black/20 bg-[#141617] shadow-2xl">
        <div className="flex gap-1.5 border-b border-white/10 px-4 py-3">
          <span className="size-2.5 rounded-full bg-[#e8836f]" />
          <span className="size-2.5 rounded-full bg-[#e0a44a]" />
          <span className="size-2.5 rounded-full bg-[#8ac898]" />
        </div>
        <pre className="space-y-1.5 px-5 py-5 font-mono text-[11px] leading-relaxed sm:text-[13px]">
          {lines.map(([c, t]) => (
            <div key={t} style={{ color: c }}>
              {t}
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}

/** Right-hand visual of a use-case card: a mini PR status panel. */
export function CaseVisual({ title, status, tone }: { title: string; status: string; tone: string }) {
  return (
    <div className="relative flex h-full min-h-[280px] items-center justify-center overflow-hidden" style={{ background: tone }}>
      <PixelCorner className="absolute right-0 top-0 size-16" />
      <div className="w-[78%] rounded-xl bg-white p-5 shadow-2xl">
        <p className="font-mono text-[11px] text-[#6b7378]">pull request · #128</p>
        <p className="mt-1 text-[15px] font-medium text-[#111]">{title}</p>
        <div className="mt-4 space-y-2">
          {["Secret Shield", "Dependency Trust", "Revue IA"].map((m, i) => (
            <div key={m} className="flex items-center justify-between rounded-md bg-[#eceef0] px-3 py-2 text-[12px] text-[#111]">
              <span>{m}</span>
              <span className={i === 0 && status === "bloqué" ? "text-[#bb3e2c]" : "text-[#3f7a52]"}>
                {i === 0 && status === "bloqué" ? "✗ secret" : "✓ ok"}
              </span>
            </div>
          ))}
        </div>
        <p className={`mt-4 text-[12px] font-medium ${status === "bloqué" ? "text-[#bb3e2c]" : "text-[#3f7a52]"}`}>
          Décision : {status}
        </p>
      </div>
    </div>
  );
}
