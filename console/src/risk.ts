/** Risk skoru düzeyi; sunucudaki cve.RiskLevel ile aynı eşikler. */
export function riskLevel(score: number): "urgent" | "high" | "medium" | "low" {
  if (score >= 80) return "urgent";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}
