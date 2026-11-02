"use client";

import { useState } from "react";
import { Star } from "lucide-react";

/** Value statements per target profile (cahier des charges §4). */
const VOICES = [
  {
    who: "Développeur solo",
    role: "Profil type",
    initials: "DS",
    quote:
      "« Je peux utiliser l'IA pour coder vite, sans envoyer par accident mes clés API ni déployer une faille critique. »",
  },
  {
    who: "Startup SaaS",
    role: "Profil type",
    initials: "ST",
    quote:
      "« Toutes nos pull requests générées par IA sont analysées, priorisées et tracées avant la production. »",
  },
  {
    who: "Agence web",
    role: "Profil type",
    initials: "AG",
    quote:
      "« Nous livrons nos projets clients avec une politique de sécurité vérifiable, même quand le code est généré par IA. »",
  },
];

export function Voices() {
  const [i, setI] = useState(0);
  const v = VOICES[i]!;
  return (
    <div className="mx-auto max-w-[1000px] text-center">
      <p key={i} className="font-display mx-auto text-[28px] leading-[1.3] text-white transition-opacity duration-500 sm:text-[38px]">
        {v.quote}
      </p>
      <div className="mt-8 flex justify-center gap-1.5" aria-label="5 sur 5">
        {Array.from({ length: 5 }).map((_, k) => (
          <Star key={k} className="size-6 fill-[#8ac898] text-[#8ac898]" aria-hidden />
        ))}
      </div>
      <div className="mx-auto mt-12 grid max-w-[900px] gap-3 sm:grid-cols-3">
        {VOICES.map((p, k) => (
          <button
            key={p.who}
            onClick={() => setI(k)}
            className={`flex cursor-pointer items-center gap-3 rounded-md px-5 py-4 text-left transition-colors duration-200 ${
              k === i ? "bg-[#232527]" : "bg-[#18191a] hover:bg-[#1f2122]"
            }`}
          >
            <span className="flex size-11 items-center justify-center rounded-full bg-[#bb3e2c] font-mono text-sm text-white">
              {p.initials}
            </span>
            <span>
              <span className="block text-[15px] text-white">{p.who}</span>
              <span className="block text-[13px] text-[#9aa3a8]">{p.role}</span>
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
