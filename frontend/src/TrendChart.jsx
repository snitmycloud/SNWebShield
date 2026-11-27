import React, { useEffect, useState } from "react";
import { TrendingUp } from "lucide-react";
import { api } from "./lib/api.js";
import { trendGeometry, trendSummary } from "./lib/monitor.js";

// The security score after each finished scan. Plain SVG; every number is also written out in text and in the table below the chart.

export function useTrend(siteId, refreshKey) {
  const [points, setPoints] = useState(null);
  useEffect(() => {
    let alive = true;
    api.websiteTrend(siteId).then(d => alive && setPoints(d.points || [])).catch(() => alive && setPoints([]));
    return () => { alive = false; };
  }, [siteId, refreshKey]);
  return points;
}

export default function TrendChart({ siteId, refreshKey }) {
  const points = useTrend(siteId, refreshKey);
  if (points === null) return <div className="loading-rows"><div /></div>;
  const geo = trendGeometry(points);
  const last = points[points.length - 1];
  return <section className="panel sw-trend" data-testid="trend-chart">
    <h3><TrendingUp size={15} /> Score trend</h3>
    {!geo.enough ? <p className="sw-note" data-testid="trend-empty">{trendSummary(points)}</p> : <>
      <p className="sw-changes-summary" data-testid="trend-summary">{trendSummary(points)}</p>
      <svg viewBox="0 0 560 160" role="img" aria-label={`Score over the last ${points.length} scans, now ${last.score} out of 100`} className="sw-trend-svg">
        {[0, 25, 50, 75, 100].map(v => <g key={v}><line x1="32" x2="550" y1={10 + ((100 - v) * 140) / 100} y2={10 + ((100 - v) * 140) / 100} className="sw-trend-grid" />
          <text x="26" y={14 + ((100 - v) * 140) / 100} textAnchor="end" className="sw-trend-axis">{v}</text></g>)}
        <path d={geo.path} className="sw-trend-line" />
        {geo.dots.map((d, i) => <circle key={i} cx={d.x} cy={d.y} r="3.5" className={`sw-trend-dot${d.incomplete ? " incomplete" : ""}`}><title>{`${new Date(d.at).toLocaleDateString("en-IN")}: ${d.score}/100 (${d.grade})${d.incomplete ? ", incomplete scan" : ""}`}</title></circle>)}
      </svg>
      <p className="sw-note">Each dot is one scan, 0 to 100 (higher is better). Hollow dots are incomplete scans, so the real score could be lower.</p></>}
  </section>;
}
