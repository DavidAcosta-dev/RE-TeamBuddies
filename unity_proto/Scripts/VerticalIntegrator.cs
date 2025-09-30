using UnityEngine;
using static TeamBuddies.Physics.FixedPoint;

namespace TeamBuddies.Gameplay
{
    public enum VerticalMode
    {
        None,
        TableIndexed,   // y = globalBase + sec[0x30]
        ResourceLookup, // y from resource handle via callback (placeholder)
        SimpleGravity   // fallback: y += vy>>12, vy += g
    }

    public class VerticalIntegrator : MonoBehaviour
    {
        [Header("Config")]
        public VerticalMode mode = VerticalMode.TableIndexed;
        [Tooltip("Global baseline Y (fixed Q12)")]
        public int globalBaseY = FromFloat(0);

        [Header("State (Fixed Q12)")]
        public int posY;
        public int velY;
        public int gravity = FromFloat(-9.81f) / 60; // approx per-frame

        [Header("Secondary Surrogates")]
        [Tooltip("Secondary[0x30] surrogate: per-frame vertical delta in fixed Q12")] public int secIdx30Delta;
        [Tooltip("Secondary+0x40 surrogate: handle/id for resource lookup")] public int secHandle0x40;
        [Tooltip("Secondary+0x60 surrogate: active flag/timer (>=0 active)")] public short secFlag0x60 = -1;

        public void Step()
        {
            switch (mode)
            {
                case VerticalMode.TableIndexed:
                    if (secFlag0x60 >= 0)
                    {
                        posY = globalBaseY + secIdx30Delta; // mimic sVar3 = base + sec[0x30]
                    }
                    break;
                case VerticalMode.ResourceLookup:
                    // Placeholder: in native, handle at +0x40 feeds func_0x00095d6c and drives bounds/coords
                    // Here we simply add a stub delta to demonstrate pluggability
                    posY += (velY >> 12);
                    break;
                case VerticalMode.SimpleGravity:
                    posY += (velY >> 12);
                    velY += gravity;
                    break;
                case VerticalMode.None:
                default:
                    break;
            }
        }

        public float PosYFloat() => ToFloat(posY);
    }
}


//--VerticalIntegrator.cs about: 
// This script handles vertical movement integration for game objects, supporting multiple modes of operation.