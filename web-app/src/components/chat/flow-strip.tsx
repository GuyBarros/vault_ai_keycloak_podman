'use client';

import { useEffect, useRef, useState } from 'react';

type NodeDef = {
  key: string;
  x: number;
  y: number;
  label: string[];
  color: string;
};

const AGENT_Y = 55;
const HUB_Y = 165;
const TOOL_Y = 280;
const ARC_DIP = 60;

const NODES: NodeDef[] = [
  { key: 'agent', x: 420, y: AGENT_Y, label: ['AI Agent'], color: '#009d9a' },
  { key: 'user', x: 70, y: HUB_Y, label: ['User'], color: '#0f62fe' },
  { key: 'webapp', x: 245, y: HUB_Y, label: ['Web App'], color: '#33b1ff' },
  { key: 'policy', x: 420, y: HUB_Y, label: ['AI Gateway', '(LiteLLM)'], color: '#8a3ffc' },
  { key: 'obo', x: 770, y: HUB_Y, label: ['token-exchange', '(OBO)'], color: '#ee5396' },
  { key: 'verify', x: 1080, y: HUB_Y, label: ['Keycloak'], color: '#da1e28' },
  { key: 'mcp', x: 770, y: TOOL_Y, label: ['user-mcp'], color: '#198038' },
  { key: 'vault', x: 1080, y: TOOL_Y, label: ['Vault'], color: '#ff832b' },
  { key: 'db', x: 1340, y: TOOL_Y, label: ['Database'], color: '#6929c4' },
];

const NODE_BY_KEY: Record<string, NodeDef> = Object.fromEntries(
  NODES.map((n) => [n.key, n] as const),
);

const R = 11;
const POLICY_R = 17;
const radiusOf = (key: string) => (key === 'policy' ? POLICY_R : R);

const BOUNDARY = { x: 350, y: 25, width: 140, height: 200 };

function lineSegment(fromKey: string, toKey: string, headRoom = 8) {
  const a = NODE_BY_KEY[fromKey]!;
  const b = NODE_BY_KEY[toKey]!;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  const ra = radiusOf(fromKey);
  const rb = radiusOf(toKey);
  return `M ${a.x + ux * (ra + 2)} ${a.y + uy * (ra + 2)} L ${b.x - ux * (rb + headRoom)} ${b.y - uy * (rb + headRoom)}`;
}

function verticalOffset(fromKey: string, toKey: string, xOffset: number, headRoom = 8) {
  const a = NODE_BY_KEY[fromKey]!;
  const b = NODE_BY_KEY[toKey]!;
  const ra = radiusOf(fromKey);
  const rb = radiusOf(toKey);
  const down = b.y > a.y;
  const sy = a.y + (down ? ra + 2 : -(ra + 2));
  const ey = b.y + (down ? -(rb + headRoom) : rb + headRoom);
  return `M ${a.x + xOffset} ${sy} L ${b.x + xOffset} ${ey}`;
}

type Edge = { d: string; arrowEnd?: boolean };

const STATIC_EDGES: Edge[] = [
  { d: lineSegment('user', 'webapp'), arrowEnd: true },
  { d: lineSegment('webapp', 'policy'), arrowEnd: true },
  { d: lineSegment('policy', 'obo'), arrowEnd: true },
  { d: lineSegment('obo', 'verify'), arrowEnd: true },

  { d: verticalOffset('policy', 'agent', -7), arrowEnd: true },
  { d: verticalOffset('agent', 'policy', +7), arrowEnd: true },

  { d: lineSegment('policy', 'mcp') },

  { d: lineSegment('mcp', 'vault'), arrowEnd: true },
  {
    d: `M ${NODE_BY_KEY.mcp!.x + R + 2} ${TOOL_Y + 2} Q ${(NODE_BY_KEY.mcp!.x + NODE_BY_KEY.db!.x) / 2} ${TOOL_Y + ARC_DIP} ${NODE_BY_KEY.db!.x - R - 10} ${TOOL_Y + 4} L ${NODE_BY_KEY.db!.x - R - 6} ${TOOL_Y}`,
    arrowEnd: true,
  },
];

const N = NODE_BY_KEY;

// Single continuous motion path. The streak follows the full lifecycle in one
// unbroken stroke: every visit to AI Agent is bracketed by Policy Engine, and
// every tool result returns through the boundary before reaching the user.
const MID_MCP_DB_X = (N.mcp!.x + N.db!.x) / 2;
const MOTION_PATH = [
  `M ${N.user!.x} ${HUB_Y}`,
  `L ${N.webapp!.x} ${HUB_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.agent!.x} ${AGENT_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.obo!.x} ${HUB_Y}`,
  `L ${N.verify!.x} ${HUB_Y}`,
  `L ${N.obo!.x} ${HUB_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.agent!.x} ${AGENT_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.mcp!.x} ${TOOL_Y}`,
  `L ${N.vault!.x} ${TOOL_Y}`,
  `L ${N.mcp!.x} ${TOOL_Y}`,
  `Q ${MID_MCP_DB_X} ${TOOL_Y + ARC_DIP} ${N.db!.x} ${TOOL_Y}`,
  `Q ${MID_MCP_DB_X} ${TOOL_Y + ARC_DIP} ${N.mcp!.x} ${TOOL_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.agent!.x} ${AGENT_Y}`,
  `L ${N.policy!.x} ${HUB_Y}`,
  `L ${N.webapp!.x} ${HUB_Y}`,
  `L ${N.user!.x} ${HUB_Y}`,
].join(' ');

const TRAIL_OFFSETS = [0, 0.18, 0.34, 0.5, 0.66];
const MOTION_DUR = 35;
// Each pass through the policy↔agent gate gets this much extra time relative
// to its physical length, so the streak visibly slows while crossing the
// boundary and the captions on those legs stay readable.
const POLICY_AGENT_SLOWDOWN = 3;

// Labels that travel with the streak. Order matches the segments of MOTION_PATH.
const SEGMENT_LABELS = [
  'subject_token + prompt', // user → webapp
  'subject_token + prompt', // webapp → policy
  'subject_token + verified prompt', // policy → agent
  'subject_token + actor_token + scopes', // agent → policy
  'subject_token + actor_token + scopes', // policy → obo
  'subject_token + actor_token + scopes', // obo → verify
  'OBO token', // verify → obo
  'OBO token', // obo → policy
  'OBO token', // policy → agent
  'OBO token', // agent → policy
  'OBO token', // policy → mcp
  'OBO token', // mcp → vault
  'JIT DB creds', // vault → mcp
  'JIT DB creds', // mcp → db (arc)
  'result', // db → mcp (arc)
  'result', // mcp → policy
  'result', // policy → agent
  'sanitized result', // agent → policy
  'sanitized result', // policy → webapp
  'sanitized result', // webapp → user
];

// Endpoint pairs for each segment, used to identify policy↔agent legs that
// should be slowed down.
const SEGMENT_NODES: ReadonlyArray<readonly [string, string]> = [
  ['user', 'webapp'],
  ['webapp', 'policy'],
  ['policy', 'agent'],
  ['agent', 'policy'],
  ['policy', 'obo'],
  ['obo', 'verify'],
  ['verify', 'obo'],
  ['obo', 'policy'],
  ['policy', 'agent'],
  ['agent', 'policy'],
  ['policy', 'mcp'],
  ['mcp', 'vault'],
  ['vault', 'mcp'],
  ['mcp', 'db'],
  ['db', 'mcp'],
  ['mcp', 'policy'],
  ['policy', 'agent'],
  ['agent', 'policy'],
  ['policy', 'webapp'],
  ['webapp', 'user'],
];

// Q-arc lengths are approximated via the average of chord and control polygon
// — accurate enough at this resolution.
const SEGMENT_LENGTHS = [
  175, 175, 110, 110, 350, 310, 310, 350, 110, 110,
  368, 310, 310, 580, 580, 368, 110, 110, 175, 175,
];

const isPolicyAgent = (i: number) => {
  const [from, to] = SEGMENT_NODES[i]!;
  return (
    (from === 'policy' && to === 'agent') ||
    (from === 'agent' && to === 'policy')
  );
};

// Weights drive how much DURATION each segment consumes; lengths drive how
// much PATH each segment covers. Where weight > length proportion, the streak
// spends more time per unit distance — i.e. moves slower.
const SEGMENT_WEIGHTS = SEGMENT_LENGTHS.map((len, i) =>
  isPolicyAgent(i) ? len * POLICY_AGENT_SLOWDOWN : len,
);

const TOTAL_LENGTH = SEGMENT_LENGTHS.reduce((a, b) => a + b, 0);
const TOTAL_WEIGHT = SEGMENT_WEIGHTS.reduce((a, b) => a + b, 0);

const cumulative = (arr: readonly number[]) =>
  arr.reduce<number[]>(
    (acc, v) => {
      const last = acc[acc.length - 1] ?? 0;
      acc.push(last + v);
      return acc;
    },
    [0],
  );

// keyPoints (path-distance fractions) and keyTimes (time fractions) for
// animateMotion calcMode="linear". Same length, both start at 0 and end at 1.
const PATH_POINTS = cumulative(SEGMENT_LENGTHS).map((l) => l / TOTAL_LENGTH);
const TIME_POINTS = cumulative(SEGMENT_WEIGHTS).map((w) => w / TOTAL_WEIGHT);

const KEY_POINTS_STR = PATH_POINTS.map((p) => p.toFixed(4)).join(';');
const KEY_TIMES_STR = TIME_POINTS.map((t) => t.toFixed(4)).join(';');

// Label opacity windows are time-based, not path-based — they need to follow
// the streak's actual position in time, which is now non-uniform.
const segmentFraction = (idx: number) =>
  (TIME_POINTS[idx] ?? 0).toFixed(4);

export function FlowStrip() {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mq.matches);
    const onChange = () => setReducedMotion(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    if (reducedMotion || collapsed) {
      svg.pauseAnimations?.();
    } else {
      svg.unpauseAnimations?.();
    }
  }, [reducedMotion, collapsed]);

  const handleEnter = () => {
    if (!collapsed) svgRef.current?.pauseAnimations?.();
  };
  const handleLeave = () => {
    if (!reducedMotion && !collapsed) svgRef.current?.unpauseAnimations?.();
  };

  return (
    <section
      className={`flow-strip${collapsed ? ' flow-strip--collapsed' : ''}`}
      aria-label="Agent request flow"
    >
      <div className="flow-strip__header">
        <span className="flow-strip__title">Request &amp; response flow</span>
        <button
          type="button"
          className="flow-strip__toggle"
          aria-expanded={!collapsed}
          aria-controls="flow-strip-body"
          onClick={() => setCollapsed((c) => !c)}
        >
          <span className="flow-strip__toggle-label">
            {collapsed ? 'Show' : 'Hide'}
          </span>
          <svg
            className="flow-strip__chevron"
            width="14"
            height="14"
            viewBox="0 0 16 16"
            aria-hidden="true"
          >
            <path
              d="M3 6l5 5 5-5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </button>
      </div>

      <div
        id="flow-strip-body"
        className="flow-strip__body"
        hidden={collapsed}
        onMouseEnter={handleEnter}
        onMouseLeave={handleLeave}
      >
        <svg
          ref={svgRef}
          className="flow-strip__svg"
          viewBox="0 0 1500 360"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-hidden="true"
        >
          <defs>
            <marker
              id="fs-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" className="fs-arrow-head" />
            </marker>
            <path id="fs-motion-path" d={MOTION_PATH} fill="none" />

            <radialGradient id="fs-policy-halo" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#8a3ffc" stopOpacity="0.28" />
              <stop offset="60%" stopColor="#8a3ffc" stopOpacity="0.08" />
              <stop offset="100%" stopColor="#8a3ffc" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Policy halo behind everything else. */}
          <circle
            cx={N.policy!.x}
            cy={N.policy!.y}
            r={POLICY_R + 22}
            fill="url(#fs-policy-halo)"
          />

          {/* Policy Boundary box wrapping AI Agent and Policy Engine. */}
          <rect
            className="fs-boundary"
            x={BOUNDARY.x}
            y={BOUNDARY.y}
            width={BOUNDARY.width}
            height={BOUNDARY.height}
            rx={8}
            ry={8}
          />
          <text
            className="fs-boundary-title"
            x={BOUNDARY.x + 8}
            y={BOUNDARY.y + 14}
          >
            POLICY BOUNDARY
          </text>

          {/* Static edges. */}
          {STATIC_EDGES.map((e, i) => (
            <path
              key={i}
              className="fs-edge"
              d={e.d}
              markerEnd={e.arrowEnd ? 'url(#fs-arrow)' : undefined}
            />
          ))}

          {/* "Intent / Tool / Required Scope" label sits above the policy → obo arrow. */}
          <text
            x={(N.policy!.x + N.obo!.x) / 2}
            y={HUB_Y - 10}
            textAnchor="middle"
            className="fs-annotation"
          >
            Intent / Tool / Required Scope
          </text>

          {/* Nodes. */}
          {NODES.map((n) => (
            <g key={n.key} className="fs-node" data-key={n.key}>
              <circle
                cx={n.x}
                cy={n.y}
                r={radiusOf(n.key)}
                style={{ fill: n.color, stroke: n.color }}
              />
              {n.label.map((line, i) => (
                <text
                  key={i}
                  x={n.x}
                  y={n.y + radiusOf(n.key) + 22 + i * 18}
                  textAnchor="middle"
                  className="fs-label"
                >
                  {line}
                </text>
              ))}
            </g>
          ))}

          {/* Single streak: lead particle + 4 trailing copies. */}
          <g className="fs-particles">
            {TRAIL_OFFSETS.map((offset, i) => {
              const opacity = Math.max(0.18, 1 - i * 0.2);
              const r = Math.max(2.5, 5 - i * 0.6);
              return (
                <circle key={i} r={r} className="fs-particle" style={{ opacity }}>
                  <animateMotion
                    dur={`${MOTION_DUR}s`}
                    begin={`${offset}s`}
                    repeatCount="indefinite"
                    calcMode="linear"
                    keyPoints={KEY_POINTS_STR}
                    keyTimes={KEY_TIMES_STR}
                  >
                    <mpath href="#fs-motion-path" />
                  </animateMotion>
                </circle>
              );
            })}
          </g>

          {/* Traveling segment labels — one <text> per segment, all riding the
              same motion path; opacity windows make exactly one visible at a
              time so the caption swaps as the streak crosses each component. */}
          <g className="fs-flow-labels">
            {SEGMENT_LABELS.map((label, i) => {
              const isFirst = i === 0;
              const isLast = i === SEGMENT_LABELS.length - 1;
              const f0 = segmentFraction(i);
              const f1 = segmentFraction(i + 1);
              const keyTimes = isFirst
                ? `0;${f1};1`
                : isLast
                  ? `0;${f0};1`
                  : `0;${f0};${f1};1`;
              const values = isFirst
                ? '1;0;0'
                : isLast
                  ? '0;1;1'
                  : '0;1;0;0';
              return (
                <g key={i}>
                  <text
                    y={-18}
                    textAnchor="middle"
                    className="fs-flow-label"
                    opacity={0}
                  >
                    {label}
                    <animate
                      attributeName="opacity"
                      dur={`${MOTION_DUR}s`}
                      repeatCount="indefinite"
                      calcMode="discrete"
                      keyTimes={keyTimes}
                      values={values}
                    />
                  </text>
                  <animateMotion
                    dur={`${MOTION_DUR}s`}
                    repeatCount="indefinite"
                    rotate="0"
                    calcMode="linear"
                    keyPoints={KEY_POINTS_STR}
                    keyTimes={KEY_TIMES_STR}
                  >
                    <mpath href="#fs-motion-path" />
                  </animateMotion>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </section>
  );
}
