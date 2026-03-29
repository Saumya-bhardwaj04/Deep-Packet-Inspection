export default function StatCard({ label, value, accent }) {
  return (
    <article className="stat-card" style={{ borderColor: accent }}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
