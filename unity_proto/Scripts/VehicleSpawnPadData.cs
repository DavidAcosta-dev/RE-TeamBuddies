using System;
using UnityEngine;

namespace TeamBuddies.Gameplay
{
    [CreateAssetMenu(menuName = "Team Buddies/Vehicle Spawn Pad", fileName = "VehicleSpawnPadData")]
    public sealed class VehicleSpawnPadData : ScriptableObject
    {
        [Header("Pad Identity")]
        [Tooltip("Friendly name for this pad snapshot; used only for editor selection.")]
        public string padName = "Unnamed Pad";

        [Header("Vertical Integrator Seed (Fixed Q12)")]
        [Tooltip("Global baseline Y (actor+0x30 equivalent).")]
        public int globalBaseY;

        [Tooltip("Initial vertical position copied into VerticalIntegrator.posY.")]
        public int initialPosY;

        [Tooltip("Initial vertical velocity copied into VerticalIntegrator.velY.")]
        public int initialVelY;

        [Tooltip("Secondary[0x30] surrogate; drives the indexed table delta.")]
        public int secIdx30Delta;

        [Tooltip("Secondary+0x40 surrogate representing the handle/id observed in RE logs.")]
        public int secHandle0x40;

        [Tooltip("Secondary+0x60 surrogate flag/timer. Negative means inactive per RE traces.")]
        public short secFlag0x60 = -1;

        [Header("Spawn Gate Observations")]
        [Tooltip("Throttle accumulator delta written to _DAT_80053b84 (default +0xA).")]
        public int throttleIncrement = 0x0A;

        [Tooltip("HUD byte offset range (actor+0x57..0x5b). This is documentation only.")]
        public Vector2Int hudByteRange = new Vector2Int(0x57, 0x5B);

        [Tooltip("Overlay address observed for the primary constructor stub.")]
        public int overlayStubAddress = 0x800348a0;

        [Tooltip("Overlay address observed for the HUD trigger stub.")]
        public int overlayHudAddress = 0x80034a38;

        [Header("Seat Descriptors")]
        [Tooltip("Seat roster entries staged at actor+0x5d. CapabilityMask mirrors the 0xFF/0x01 logic.")]
        public SeatDescriptor[] seats = Array.Empty<SeatDescriptor>();

        [Header("Fallback Behaviour")]
        [Tooltip("Integrator mode we expect this pad to use once spawned.")]
        public VerticalMode fallbackMode = VerticalMode.TableIndexed;

        [Tooltip("Optional notes pulled directly from the reverse-engineering log.")]
        [TextArea]
        public string findingsNotes;

        [Serializable]
        public struct SeatDescriptor
        {
            [Tooltip("Index into the seat roster array (actor+0x5d).")]
            public int seatIndex;

            [Tooltip("Capability mask derived from RE (0xFF or 0x01 etc.).")]
            public int capabilityMask;

            [Tooltip("Label to clarify which crew member / crate mapping this represents.")]
            public string label;
        }

        /// <summary>
        /// Pushes the captured pad data into a live <see cref="VerticalIntegrator"/> component.
        /// </summary>
        /// <param name="integrator">Target integrator.</param>
        /// <param name="overwriteRuntimeState">
        /// When true, runtime fields (pos/vel) are reset to the stored snapshot before applying mode/secondary data.
        /// </param>
        public void ApplyTo(VerticalIntegrator integrator, bool overwriteRuntimeState = true)
        {
            if (integrator == null)
            {
                return;
            }

            integrator.mode = fallbackMode;
            integrator.globalBaseY = globalBaseY;
            integrator.secIdx30Delta = secIdx30Delta;
            integrator.secHandle0x40 = secHandle0x40;
            integrator.secFlag0x60 = secFlag0x60;

            if (overwriteRuntimeState)
            {
                integrator.posY = initialPosY;
                integrator.velY = initialVelY;
            }
        }
    }
}
