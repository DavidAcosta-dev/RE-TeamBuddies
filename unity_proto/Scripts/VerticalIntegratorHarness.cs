using System;
using UnityEngine;

namespace TeamBuddies.Gameplay
{
    /// <summary>
    /// Lightweight harness that keeps multiple <see cref="VerticalIntegrator"/> instances in lockstep
    /// so we can validate different RE snapshots side-by-side inside the editor or in play mode.
    /// </summary>
    [ExecuteAlways]
    public sealed class VerticalIntegratorHarness : MonoBehaviour
    {
        [Header("Targets")]
        [Tooltip("Integrators that will be driven by this harness.")]
        public VerticalIntegrator[] integrators = Array.Empty<VerticalIntegrator>();

        [Header("Snapshots")]
        [Tooltip("Optional pad data snapshots captured from reverse-engineering work. Each entry is pushed to the integrator with the same index.")]
        public VehicleSpawnPadData[] padSnapshots = Array.Empty<VehicleSpawnPadData>();

        [Header("Behaviour")]
        [Tooltip("Reset integrator state from pad data on Start / enable.")]
        public bool applySnapshotsOnEnable = true;

        [Tooltip("Automatically call Step() every frame while playing.")]
        public bool stepDuringPlayMode = true;

        [Tooltip("Should we tick in edit mode as well? Useful when scrubbing values without entering play mode.")]
        public bool stepDuringEditMode;

        private float accumulatedTime;

        private void OnEnable()
        {
            if (applySnapshotsOnEnable)
            {
                ApplySnapshots();
            }
        }

        private void Update()
        {
            if (Application.isPlaying)
            {
                if (stepDuringPlayMode)
                {
                    StepAll();
                }
            }
#if UNITY_EDITOR
            else if (!Application.isPlaying && stepDuringEditMode)
            {
                var deltaTime = Time.deltaTime;
                accumulatedTime += deltaTime;
                // Step roughly once per frame; deltaTime in edit mode can fluctuate, so keep it simple.
                if (accumulatedTime >= (1f / 60f))
                {
                    StepAll();
                    accumulatedTime = 0f;
                }
            }
#endif
        }

        [ContextMenu("Apply Snapshots")]
        public void ApplySnapshots()
        {
            if (integrators == null)
            {
                return;
            }

            for (int i = 0; i < integrators.Length; i++)
            {
                var integrator = integrators[i];
                if (integrator == null)
                {
                    continue;
                }

                if (padSnapshots != null && i < padSnapshots.Length)
                {
                    padSnapshots[i]?.ApplyTo(integrator, overwriteRuntimeState: true);
                }
            }
        }

        [ContextMenu("Step All Once")]
        public void StepAll()
        {
            if (integrators == null)
            {
                return;
            }

            foreach (var integrator in integrators)
            {
                integrator?.Step();
            }
        }
    }
}
