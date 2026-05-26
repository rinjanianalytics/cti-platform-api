import { AlertCircle, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { SchedulerInfo } from "@/core/types";
import { useEditRepeatableScheduler } from "@/lib/hooks";

interface IntervalPreset {
  value: string;
  label: string;
  cron: string;
}

interface EditSchedulerDialogProps {
  scheduler: SchedulerInfo | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  intervalPresets: IntervalPreset[];
}

const DEFAULT_VALUE = "__default__";

/**
 * Inline cron classifier — match the scheduler's current pattern against the
 * configured presets so the Select can highlight the active row when the
 * dialog opens. Falls back to "default" when no preset matches.
 */
function detectActivePreset(
  scheduler: SchedulerInfo,
  presets: IntervalPreset[],
): string {
  if (!scheduler.pattern) return DEFAULT_VALUE;
  const match = presets.find((p) => p.cron === scheduler.pattern);
  return match?.value ?? DEFAULT_VALUE;
}

export function EditSchedulerDialog({
  scheduler,
  open,
  onOpenChange,
  intervalPresets,
}: EditSchedulerDialogProps) {
  const mutation = useEditRepeatableScheduler();

  const [selected, setSelected] = useState<string>(DEFAULT_VALUE);

  // Reset selection whenever the dialog target changes — without this the
  // previous job's value would persist when the operator picks a new row.
  useEffect(() => {
    if (scheduler && open) {
      setSelected(detectActivePreset(scheduler, intervalPresets));
      mutation.reset();
    }
  }, [scheduler, open, intervalPresets, mutation.reset]);

  if (!scheduler) return null;

  const handleSave = () => {
    mutation.mutate(
      {
        queueName: scheduler.queueName,
        jobName: scheduler.name,
        intervalPreset: selected === DEFAULT_VALUE ? null : selected,
        enabled: true,
      },
      {
        onSuccess: () => {
          onOpenChange(false);
        },
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            Edit schedule
            <span className="ml-2 font-mono text-sm text-muted-foreground">
              {scheduler.name}
            </span>
          </DialogTitle>
          <DialogDescription>
            Pick a curated interval preset. Free-form cron isn't editable
            from the UI — a bad expression is a trivial self-DoS.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-2">
          <div className="space-y-1.5">
            <label className="text-xs uppercase tracking-wider text-muted-foreground">
              Interval
            </label>
            <Select value={selected} onValueChange={setSelected}>
              <SelectTrigger className="h-9 w-full text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={DEFAULT_VALUE}>
                  Use code default
                </SelectItem>
                {intervalPresets.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                    <span className="ml-2 font-mono text-[10px] text-muted-foreground/70">
                      {p.cron}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="rounded border border-dashed border-border bg-muted/30 p-2 text-[11px] text-muted-foreground">
            <span className="font-mono">Queue:</span> {scheduler.queueName}
            {scheduler.pattern && (
              <>
                <br />
                <span className="font-mono">Current:</span> {scheduler.pattern}
              </>
            )}
          </div>

          {mutation.error && (
            <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
              <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
              <span>{(mutation.error as Error).message}</span>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={mutation.isPending}
          >
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={mutation.isPending}>
            {mutation.isPending ? (
              <>
                <Loader2 className="size-3.5 animate-spin" />
                Saving…
              </>
            ) : (
              "Save"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
