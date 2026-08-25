export interface RunSummary {
  git: {
    is_release: boolean;
    dirty: boolean;
    branch: string | null;
    commit: string | null;
    github: string | null;
  };
  version: string;
  id: string;
  timestamp: string;
  status: string;
  status_color: string;
  case_count: number;
  avg_similarity: number | null;
}
