import { jsPDF } from "jspdf";

/**
 * Generate a styled Shadow Hunter PDF report from backend report data.
 * Uses jsPDF for client-side PDF generation — no server dependencies.
 */
export function generatePdfReport(report) {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentW = pageW - margin * 2;
  let y = margin;

  // ── Colors ──
  const colors = {
    bg: [15, 23, 42], // slate-900
    panel: [30, 41, 59], // slate-800
    accent: [239, 68, 68], // red-500
    blue: [59, 130, 246],
    amber: [245, 158, 11],
    cyan: [6, 182, 212],
    textPrimary: [226, 232, 240],
    textSecondary: [148, 163, 184],
    textMuted: [100, 116, 139],
    border: [51, 65, 85],
  };

  // ── Helper: draw filled rect ──
  const drawRect = (x, ry, w, h, color, radius = 0) => {
    doc.setFillColor(...color);
    if (radius > 0) {
      doc.roundedRect(x, ry, w, h, radius, radius, "F");
    } else {
      doc.rect(x, ry, w, h, "F");
    }
  };

  // ── Helper: check page break ──
  const checkPageBreak = (needed) => {
    if (y + needed > pageH - margin) {
      doc.addPage();
      drawRect(0, 0, pageW, pageH, colors.bg);
      y = margin;
      return true;
    }
    return false;
  };

  // ══════════════════════════════════════════════
  // PAGE 1 — Cover
  // ══════════════════════════════════════════════
  drawRect(0, 0, pageW, pageH, colors.bg);

  // Red accent bar at top
  drawRect(0, 0, pageW, 3, colors.accent);

  // Logo area
  y = 50;
  drawRect(margin, y, 14, 14, [239, 68, 68, 0.1]);
  doc.setDrawColor(...colors.accent);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, y, 14, 14, 2, 2, "S");

  doc.setTextColor(...colors.accent);
  doc.setFontSize(16);
  doc.setFont("helvetica", "bold");
  doc.text("SH", margin + 3.5, y + 9.5);

  // Title
  y += 25;
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(28);
  doc.setFont("helvetica", "bold");
  doc.text("Shadow Hunter", margin, y);

  y += 10;
  doc.setFontSize(14);
  doc.setTextColor(...colors.textSecondary);
  doc.setFont("helvetica", "normal");
  doc.text("Threat Intelligence Report", margin, y);

  y += 8;
  doc.setFontSize(9);
  doc.setTextColor(...colors.textMuted);
  const genDate = new Date(report.generated_at).toLocaleString([], {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  doc.text(`Generated: ${genDate}`, margin, y);

  // Separator
  y += 8;
  doc.setDrawColor(...colors.border);
  doc.setLineWidth(0.3);
  doc.line(margin, y, pageW - margin, y);

  // ── Executive Summary Cards ──
  y += 12;
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text("EXECUTIVE SUMMARY", margin, y);

  y += 8;
  const cardW = (contentW - 6) / 4;
  const summaryCards = [
    {
      label: "Total Alerts",
      value: report.summary.total_alerts,
      color: colors.cyan,
    },
    {
      label: "Shadow AI",
      value: report.summary.shadow_ai_alerts,
      color: colors.accent,
    },
    {
      label: "Unique Sources",
      value: report.summary.unique_sources,
      color: colors.blue,
    },
    {
      label: "Unique Targets",
      value: report.summary.unique_targets,
      color: colors.amber,
    },
  ];

  summaryCards.forEach((card, i) => {
    const cx = margin + i * (cardW + 2);
    drawRect(cx, y, cardW, 22, colors.panel, 2);

    // Top accent line
    drawRect(cx, y, cardW, 1.5, card.color, 1);

    doc.setTextColor(...card.color);
    doc.setFontSize(16);
    doc.setFont("helvetica", "bold");
    doc.text(String(card.value), cx + cardW / 2, y + 12, { align: "center" });

    doc.setTextColor(...colors.textMuted);
    doc.setFontSize(6);
    doc.setFont("helvetica", "normal");
    doc.text(card.label.toUpperCase(), cx + cardW / 2, y + 18, {
      align: "center",
    });
  });

  y += 30;

  // ── Severity Breakdown ──
  checkPageBreak(50);
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text("SEVERITY BREAKDOWN", margin, y);
  y += 8;

  const sevTotal =
    report.severity_breakdown.HIGH +
      report.severity_breakdown.MEDIUM +
      report.severity_breakdown.LOW || 1;
  const sevData = [
    {
      label: "HIGH",
      value: report.severity_breakdown.HIGH,
      color: [239, 68, 68],
    },
    {
      label: "MEDIUM",
      value: report.severity_breakdown.MEDIUM,
      color: [245, 158, 11],
    },
    {
      label: "LOW",
      value: report.severity_breakdown.LOW,
      color: [59, 130, 246],
    },
  ];

  drawRect(margin, y, contentW, 30, colors.panel, 2);

  sevData.forEach((s, i) => {
    const sx = margin + 8;
    const sy = y + 6 + i * 8;
    const pct = (s.value / sevTotal) * 100;

    doc.setTextColor(...s.color);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text(s.label, sx, sy + 1);

    // Bar background
    const barX = sx + 22;
    const barW = contentW - 60;
    drawRect(barX, sy - 2, barW, 4, [30, 41, 59]);

    // Bar fill
    drawRect(barX, sy - 2, barW * (pct / 100), 4, s.color, 1);

    // Count
    doc.setTextColor(...colors.textSecondary);
    doc.setFontSize(7);
    doc.text(`${s.value} (${pct.toFixed(0)}%)`, barX + barW + 3, sy + 1);
  });

  y += 38;

  // ── Top Offenders (Sources) ──
  checkPageBreak(60);
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text("TOP OFFENDING SOURCES", margin, y);
  y += 6;

  if (report.top_sources.length > 0) {
    // Table header
    drawRect(margin, y, contentW, 7, colors.panel, 1);
    doc.setTextColor(...colors.textMuted);
    doc.setFontSize(6);
    doc.setFont("helvetica", "bold");
    doc.text("#", margin + 3, y + 5);
    doc.text("SOURCE IP", margin + 12, y + 5);
    doc.text("ALERTS", pageW - margin - 20, y + 5);
    y += 8;

    const maxAlerts = report.top_sources[0]?.alert_count || 1;
    report.top_sources.slice(0, 10).forEach((src, i) => {
      checkPageBreak(8);
      const rowColor = i % 2 === 0 ? colors.bg : colors.panel;
      drawRect(margin, y, contentW, 7, rowColor);

      doc.setTextColor(...colors.textMuted);
      doc.setFontSize(7);
      doc.setFont("helvetica", "normal");
      doc.text(`${i + 1}`, margin + 3, y + 5);

      doc.setTextColor(...colors.textPrimary);
      doc.setFont("helvetica", "bold");
      doc.text(src.ip, margin + 12, y + 5);

      // Mini bar
      const barStart = margin + 75;
      const barMax = contentW - 100;
      drawRect(barStart, y + 1.5, barMax, 3, [30, 41, 59]);
      drawRect(
        barStart,
        y + 1.5,
        barMax * (src.alert_count / maxAlerts),
        3,
        i === 0 ? colors.accent : colors.blue,
        1,
      );

      doc.setTextColor(...colors.textSecondary);
      doc.setFontSize(7);
      doc.text(`${src.alert_count}`, pageW - margin - 15, y + 5);

      y += 7;
    });
  } else {
    doc.setTextColor(...colors.textMuted);
    doc.setFontSize(8);
    doc.text("No source data available", margin + 5, y + 8);
    y += 12;
  }

  y += 8;

  // ── Top Targets ──
  checkPageBreak(60);
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text("TOP TARGETED DESTINATIONS", margin, y);
  y += 6;

  if (report.top_targets.length > 0) {
    drawRect(margin, y, contentW, 7, colors.panel, 1);
    doc.setTextColor(...colors.textMuted);
    doc.setFontSize(6);
    doc.setFont("helvetica", "bold");
    doc.text("#", margin + 3, y + 5);
    doc.text("DESTINATION", margin + 12, y + 5);
    doc.text("ALERTS", pageW - margin - 20, y + 5);
    y += 8;

    const maxTargets = report.top_targets[0]?.alert_count || 1;
    report.top_targets.slice(0, 10).forEach((tgt, i) => {
      checkPageBreak(8);
      const rowColor = i % 2 === 0 ? colors.bg : colors.panel;
      drawRect(margin, y, contentW, 7, rowColor);

      doc.setTextColor(...colors.textMuted);
      doc.setFontSize(7);
      doc.text(`${i + 1}`, margin + 3, y + 5);

      doc.setTextColor(...colors.textPrimary);
      doc.setFont("helvetica", "bold");
      // Truncate long hostnames
      const displayName =
        tgt.ip.length > 40 ? tgt.ip.slice(0, 37) + "..." : tgt.ip;
      doc.text(displayName, margin + 12, y + 5);

      const barStart = margin + 75;
      const barMax = contentW - 100;
      drawRect(barStart, y + 1.5, barMax, 3, [30, 41, 59]);
      drawRect(
        barStart,
        y + 1.5,
        barMax * (tgt.alert_count / maxTargets),
        3,
        colors.amber,
        1,
      );

      doc.setTextColor(...colors.textSecondary);
      doc.setFontSize(7);
      doc.text(`${tgt.alert_count}`, pageW - margin - 15, y + 5);

      y += 7;
    });
  }

  y += 12;

  // ── Recommendations ──
  checkPageBreak(50);
  doc.setTextColor(...colors.textPrimary);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text("RECOMMENDATIONS", margin, y);
  y += 8;

  drawRect(
    margin,
    y,
    contentW,
    report.recommendations.length * 9 + 6,
    colors.panel,
    2,
  );
  y += 5;

  report.recommendations.forEach((rec, i) => {
    checkPageBreak(10);
    // Bullet
    doc.setTextColor(...colors.cyan);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text(`${i + 1}.`, margin + 5, y + 1);

    doc.setTextColor(...colors.textSecondary);
    doc.setFontSize(8);
    doc.setFont("helvetica", "normal");
    doc.text(rec, margin + 14, y + 1);

    y += 9;
  });

  y += 8;

  // ── Footer ──
  const footerY = pageH - 10;
  doc.setDrawColor(...colors.border);
  doc.setLineWidth(0.2);
  doc.line(margin, footerY - 3, pageW - margin, footerY - 3);

  doc.setTextColor(...colors.textMuted);
  doc.setFontSize(6);
  doc.text(
    "Shadow Hunter — Enterprise Shadow AI Detection Platform",
    margin,
    footerY,
  );
  doc.text("CONFIDENTIAL", pageW - margin, footerY, { align: "right" });

  // ── Save ──
  const filename = `shadow_hunter_report_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}
