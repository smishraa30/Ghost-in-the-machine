import { DottedSurface } from "@/components/ui/dotted-surface";
import { cn } from '@/lib/utils';

export default function DemoOne() {
  return (
    <DottedSurface className="size-full">
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center px-6">
        {/* Glow backdrop */}
        <div
          aria-hidden="true"
          className={cn(
            'pointer-events-none absolute -top-10 left-1/2 size-full -translate-x-1/2 rounded-full',
            'bg-[radial-gradient(ellipse_at_center,rgba(6,182,212,0.15),transparent_50%)]',
            'blur-[30px]',
          )}
        />
        
        {/* Glowing badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-mono tracking-widest uppercase mb-6 animate-pulse">
          🛡️ Phantasm Sentinel Active
        </div>

        {/* Hero Title */}
        <h1 className="font-sans text-5xl md:text-7xl font-extrabold text-white tracking-tight leading-none mb-4">
          Is your PC safe?
        </h1>
        <h2 className="font-sans text-4xl md:text-6xl font-extrabold bg-gradient-to-r from-cyan-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent mb-8">
          Use Phantasm
        </h2>

        {/* Informative description */}
        <p className="font-sans text-gray-400 text-sm md:text-base leading-relaxed max-w-xl mb-8">
          Advanced interactive deception technology that maps, profiles, and defiles network intruders in real time.
        </p>

        {/* Interactive glowing action buttons */}
        <div className="flex gap-4">
          <a 
            href="/" 
            className="px-6 py-2.5 rounded-full font-bold text-xs bg-gradient-to-r from-cyan-500 to-indigo-500 text-black shadow-[0_4px_20px_rgba(6,182,212,0.3)] hover:scale-105 transition-transform"
          >
            🐚 Open Honeypot Shell
          </a>
          <a 
            href="/dashboard" 
            className="px-6 py-2.5 rounded-full font-bold text-xs border border-white/15 text-white hover:bg-white/5 transition-colors"
          >
            📊 View Telemetry
          </a>
        </div>
      </div>
    </DottedSurface>
  );
}
