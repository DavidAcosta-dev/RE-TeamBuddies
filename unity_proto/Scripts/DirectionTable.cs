// DirectionTable: approximates (cos,sin) short pairs scaled to 4096 (0x1000) indexed by (angle & 0xFFF)
// In native: index = (FUN_00022e5c(...) & 0xFFF) * 4; table base near -0x7ffeb164.
using UnityEngine;
using static TeamBuddies.Physics.FixedPoint;

namespace TeamBuddies.Gameplay
{
    [CreateAssetMenu(menuName = "TeamBuddies/DirectionTable")]
    public class DirectionTable : ScriptableObject
    {
        [Tooltip("Precomputed (cos,sin) pairs in fixed 12-scale (length 4096)")] public Vector2Int[] pairs;
        [Header("External Data Injection")]
        [Tooltip("Optional raw table text asset: 4096 lines of 'cos sin' fixed ints.")]
        public TextAsset externalDump;
        [Tooltip("If true and externalDump present, reload on domain reload/editor change.")] public bool autoLoadExternal = true;

        private bool _loadedExternal;

        public void Generate()
        {
            pairs = new Vector2Int[4096];
            for (int i = 0; i < 4096; i++)
            {
                float ang = (i / 4096f) * Mathf.PI * 2f;
                int c = FixedPoint.FromFloat(Mathf.Cos(ang));
                int s = FixedPoint.FromFloat(Mathf.Sin(ang));
                pairs[i] = new Vector2Int(c, s);
            }
        }

        public void LoadExternalIfNeeded()
        {
            if (_loadedExternal) return;
            if (!externalDump || !autoLoadExternal) return;
            try
            {
                var lines = externalDump.text.Split('\n');
                if (lines.Length < 2048) return; // allow header / idx-prefixed formats
                if (pairs == null || pairs.Length != 4096)
                    pairs = new Vector2Int[4096];
                int filled = 0;
                foreach (var raw in lines)
                {
                    if (filled >= 4096) break;
                    var line = raw.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;
                    // Support scaffold dump format: idx,a,b,hex
                    if (line.Contains(","))
                    {
                        var partsCsv = line.Split(',');
                        if (partsCsv.Length >= 3 && int.TryParse(partsCsv[0], out int idxCsv) && idxCsv >= 0 && idxCsv < 4096)
                        {
                            if (int.TryParse(partsCsv[1], out int ac) && int.TryParse(partsCsv[2], out int bc))
                            {
                                pairs[idxCsv] = new Vector2Int(ac, bc);
                                filled = Mathf.Max(filled, idxCsv + 1);
                                continue;
                            }
                        }
                    }
                    // Accept space / bracket forms: "c s" or "[c s]" or "c,s"
                    var norm = line.Replace('[', ' ').Replace(']', ' ').Replace(',', ' ');
                    var parts = norm.Split(new[] { ' ', '\t' }, System.StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    if (int.TryParse(parts[0], out int c) && int.TryParse(parts[1], out int s))
                    {
                        pairs[filled++] = new Vector2Int(c, s);
                    }
                }
                _loadedExternal = true;
            }
            catch { /* swallow for robustness */ }
        }

        /// <summary>
        /// Inject a raw dump programmatically (e.g., editor tooling) without TextAsset.
        /// Accepts lines of either: "idx,a,b,..." or "a b". Length must be 4096 meaningful entries.
        /// </summary>
        public void InjectFromLines(string[] lines)
        {
            if (lines == null) return;
            if (pairs == null || pairs.Length != 4096) pairs = new Vector2Int[4096];
            int filled = 0;
            foreach (var raw in lines)
            {
                if (filled >= 4096) break;
                if (string.IsNullOrWhiteSpace(raw) || raw.StartsWith("#")) continue;
                var line = raw.Trim();
                if (line.Contains(","))
                {
                    var seg = line.Split(',');
                    if (seg.Length >= 3 && int.TryParse(seg[0], out int idx) && idx >= 0 && idx < 4096 && int.TryParse(seg[1], out int a) && int.TryParse(seg[2], out int b))
                    {
                        pairs[idx] = new Vector2Int(a, b);
                        filled = Mathf.Max(filled, idx + 1);
                        continue;
                    }
                }
                var norm = line.Replace('[', ' ').Replace(']', ' ').Replace(',', ' ');
                var parts = norm.Split(new[] { ' ', '\t' }, System.StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (int.TryParse(parts[0], out int c) && int.TryParse(parts[1], out int s))
                {
                    pairs[filled++] = new Vector2Int(c, s);
                }
            }
            _loadedExternal = true;
        }

        public Vector2 GetDir(int hashed)
        {
            int idx = hashed & 0xFFF; // mask like native
            if (pairs == null || pairs.Length != 4096) Generate();
            LoadExternalIfNeeded();
            var p = pairs[idx];
            return new Vector2(FixedPoint.ToFloat(p.x), FixedPoint.ToFloat(p.y));
        }
    }
}
