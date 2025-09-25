// FixedPoint helpers mirroring PSX-style Q20.12 or Q16.12 semantics (we care about >> 12 scaling)
// NOTE: Using int for intermediate to avoid overflow; external code should clamp if matching 16-bit wrapping.
namespace TeamBuddies.Physics
{
    public static class FixedPoint
    {
        public const int SHIFT = 12; // >> 0xC
        public const int ONE = 1 << SHIFT; // 4096

        public static float ToFloat(int fp) => fp / (float)ONE;
        public static int FromFloat(float f) => (int)System.MathF.Round(f * ONE);

        public static int Mul(int a, int b) => (int)((long)a * b >> SHIFT);
        public static int Div(int a, int b) => b == 0 ? 0 : (int)(((long)a << SHIFT) / b);

        public static int Lerp(int a, int b, float t)
            => a + (int)((b - a) * t);
    }
}
