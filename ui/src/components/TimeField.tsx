/** Text field of a local date and time (`YYYY-MM-DD hh:mm:ss`): Save PCAP and the range dialog. */
export function TimeField({
  label,
  value,
  onChange,
  describedBy,
  autoFocus = false,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  describedBy: string;
  autoFocus?: boolean;
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="text-meta text-muted">{label}</span>
      <input
        type="text"
        inputMode="numeric"
        spellCheck={false}
        autoComplete="off"
        value={value}
        aria-describedby={describedBy}
        {...(autoFocus ? { 'data-autofocus': true } : {})}
        onChange={(e) => {
          onChange(e.target.value);
        }}
        className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 font-mono text-body"
      />
    </label>
  );
}
