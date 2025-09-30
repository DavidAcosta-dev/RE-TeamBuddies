// CrateThrowPhysics: mirrors integrator observed in phys_FUN_000406ac
// pos -= (vel * scale >> 12) pattern; scale is a per-frame scalar (iVar10) likely derived from delta or speed factor.
using UnityEngine;
using static TeamBuddies.Physics.FixedPoint;

namespace TeamBuddies.Gameplay
{
    public class CrateThrowPhysics : MonoBehaviour
    {
        [Header("Fixed-Point State (debug view)")]
        [SerializeField] private int velX; // +0x100
        [SerializeField] private int velZ; // +0x102
        [SerializeField] private int posX; // +0x114
        [SerializeField] private int posZ; // +0x118
        [SerializeField] private int velY; // (pending offset) placeholder
        [SerializeField] private int posY; // (pending offset)

        [Header("Runtime Params")]
        [Tooltip("Frame scalar analogous to iVar10 (speed / timestep).")]
        public int frameScalar = ONE; // default 1.0 in fixed
        [Tooltip("Gravity per frame in fixed (negative). TBD from RE.")]
        public int gravityPerFrame = -(int)(0.25f * ONE); // placeholder

        [Tooltip("Convert fixed state into transform each Update")] public bool applyToTransform = true;

        public void SeedThrow(Vector3 worldVel)
        {
            velX = FromFloat(worldVel.x);
            velZ = FromFloat(worldVel.z);
            velY = FromFloat(worldVel.y);
        }

        private void Integrate()
        {
            // pos -= (vel * frameScalar >> 12) matches snippet (note subtraction in original code)
            posX -= Mul(velX, frameScalar);
            posZ -= Mul(velZ, frameScalar);
            // Y uses conventional physics: posY += velY * dt; then velY += gravity
            // To align with discovered pattern once Y integrator snippet is found we may invert sign or scale.
            posY += Mul(velY, frameScalar);
            velY += gravityPerFrame; // apply gravity (placeholder)
        }

        private void Update()
        {
            Integrate();
            if (applyToTransform)
            {
                transform.position = new Vector3(ToFloat(posX), ToFloat(posY), ToFloat(posZ));
            }
        }

#if UNITY_EDITOR
        private void OnDrawGizmosSelected()
        {
            Gizmos.color = Color.yellow;
            Gizmos.DrawWireSphere(new Vector3(ToFloat(posX), ToFloat(posY), ToFloat(posZ)), 0.1f);
        }
#endif
    }
}
