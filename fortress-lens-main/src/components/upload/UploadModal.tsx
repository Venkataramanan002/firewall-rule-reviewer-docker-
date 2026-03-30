import { useRef, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Upload,
  FileText,
  CheckCircle2,
  AlertTriangle,
  X,
  Loader2,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { uploadConfig, uploadData } from "@/lib/api";

interface UploadModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUploadComplete?: () => void;
}

const ACCEPTED = ".xml,.conf,.csv,.json,.xlsx";

const VENDOR_GUIDE = [
  { vendor: "Palo Alto (PAN-OS)", ext: ".xml", hint: "Export from Panorama -> Device -> Export Running Config" },
  { vendor: "Cisco ASA", ext: ".conf", hint: "Run 'show running-config' and save as .conf" },
  { vendor: "FortiGate", ext: ".conf", hint: "Filename should contain 'forti'" },
  { vendor: "Traffic / Log Data", ext: ".csv / .json / .xlsx", hint: "Connection logs with timestamp, src_ip, dst_ip, protocol, action" },
];

type Phase = "idle" | "uploading" | "done" | "error";

export function UploadModal({ open, onOpenChange, onUploadComplete }: UploadModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const [vendor, setVendor] = useState("");
  const [guideOpen, setGuideOpen] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function reset() {
    setFile(null);
    setPhase("idle");
    setProgress(0);
    setErrorMsg("");
    setVendor("");
    setGuideOpen(false);
  }

  function handleClose(v: boolean) {
    onOpenChange(v);
    if (!v) reset();
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) {
      setFile(f);
      setPhase("idle");
      setErrorMsg("");
    }
    e.target.value = "";
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) {
      setFile(f);
      setPhase("idle");
      setErrorMsg("");
    }
  }

  function isConfig(f: File) {
    return f.name.endsWith(".xml") || f.name.endsWith(".conf") || f.name.toLowerCase().includes("forti");
  }

  async function handleUpload() {
    if (!file) return;
    setPhase("uploading");
    setProgress(0);
    setErrorMsg("");

    let p = 0;
    const tick = setInterval(() => {
      p = Math.min(p + 2, 90);
      setProgress(p);
    }, 150);

    try {
      if (isConfig(file)) {
        const res = await uploadConfig(file);
        setVendor(res.vendor);
      } else {
        await uploadData(file);
      }

      clearInterval(tick);
      setProgress(100);
      setPhase("done");
      onUploadComplete?.();
      window.dispatchEvent(new CustomEvent("firewall-upload-complete"));
    } catch (err) {
      clearInterval(tick);
      setErrorMsg((err as Error).message || "Upload failed");
      setPhase("error");
    }
  }

  const fileSize = file
    ? file.size >= 1e6
      ? `${(file.size / 1e6).toFixed(1)} MB`
      : `${(file.size / 1024).toFixed(1)} KB`
    : "";
  const fileExt = file ? file.name.split(".").pop()?.toUpperCase() : "";

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-lg bg-card border-border">
        <DialogHeader>
          <DialogTitle className="text-[15px] font-semibold flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Upload Firewall Data
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 mt-1">
          <div className="bg-primary/5 border border-primary/20 rounded-lg p-3">
            <p className="text-[12px] text-muted-foreground">
              Drop any firewall config or traffic log file. The backend extracts
              <span className="text-foreground font-medium"> rules, zones, risk scores, attack paths, connections and threats</span> automatically.
            </p>
          </div>

          <div className="bg-secondary/30 rounded-lg overflow-hidden">
            <button
              onClick={() => setGuideOpen(!guideOpen)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-[12px] font-medium text-foreground hover:bg-secondary/50 transition-smooth"
            >
              Supported formats
              {guideOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            <div className={`overflow-hidden transition-all duration-200 ${guideOpen ? "max-h-72" : "max-h-0"}`}>
              <div className="px-4 pb-3 space-y-2">
                {VENDOR_GUIDE.map(({ vendor: v, ext, hint }) => (
                  <div key={v} className="flex gap-3">
                    <span className="text-[11px] font-mono bg-secondary px-1.5 py-0.5 rounded shrink-0 self-start">{ext}</span>
                    <div>
                      <p className="text-[11px] font-medium text-foreground">{v}</p>
                      <p className="text-[10px] text-muted-foreground">{hint}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {phase !== "done" && (
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              className="border-2 border-dashed border-muted hover:border-primary/50 transition-smooth bg-secondary/20 rounded-xl p-8 text-center cursor-pointer select-none"
            >
              <input ref={fileRef} type="file" className="hidden" accept={ACCEPTED} onChange={handleFileInput} />
              <Upload className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-[13px] text-foreground font-medium">{file ? "Replace file" : "Choose file or drag here"}</p>
              <p className="text-[11px] text-muted-foreground mt-1">.xml - .conf - .csv - .json - .xlsx</p>
            </div>
          )}

          {file && phase === "idle" && (
            <div className="flex items-center gap-3 bg-secondary/30 rounded-lg p-3">
              <FileText className="h-5 w-5 text-primary shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-medium text-foreground truncate">{file.name}</p>
                <p className="text-[10px] text-muted-foreground">{fileSize} - {fileExt}</p>
              </div>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={reset}>
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}

          {file && phase === "idle" && (
            <Button className="w-full" onClick={handleUpload}>
              <Upload className="h-4 w-4 mr-2" />
              Upload & Analyze
            </Button>
          )}

          {phase === "uploading" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Uploading and running analysis...
                </span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-1.5" />
              <p className="text-[10px] text-muted-foreground text-center">
                Parsing rules -&gt; scoring risk -&gt; building topology -&gt; calculating attack paths
              </p>
            </div>
          )}

          <AnimatePresence>
            {phase === "done" && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="rounded-lg border border-success/30 bg-success/10 p-3"
              >
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-success mt-0.5" />
                  <div>
                    <p className="text-[12px] font-semibold text-success">Upload complete</p>
                    <p className="text-[11px] text-muted-foreground">
                      Your data has been ingested successfully.
                      {vendor ? ` Detected vendor: ${vendor}.` : ""}
                    </p>
                  </div>
                </div>
              </motion.div>
            )}

            {phase === "error" && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="rounded-lg border border-destructive/30 bg-destructive/10 p-3"
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-destructive mt-0.5" />
                  <div>
                    <p className="text-[12px] font-semibold text-destructive">Upload failed</p>
                    <p className="text-[11px] text-muted-foreground break-words">{errorMsg}</p>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>
  );
}
