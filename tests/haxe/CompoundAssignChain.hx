class CompoundAssignChain {
    static function subCompound(a: Int, b: Int, c: Int): Int {
        var x = a;
        x -= b - c; // x = a - (b - c) = a - b + c
        return x;
    }

    static function divCompound(a: Int, b: Int, c: Int): Int {
        var x = a;
        x = Std.int(x / (b - c));
        return x;
    }

    static function modCompound(a: Int, b: Int, c: Int): Int {
        var x = a;
        x %= b + c;
        return x;
    }

    static function bitwiseMix(a: Int, b: Int, c: Int): Int {
        // & binds tighter than |, which binds tighter... wait | is lowest, ^ mid, & tightest
        return a & b | c;
    }

    static function bitwiseMix2(a: Int, b: Int, c: Int): Int {
        return a | b & c;
    }

    static function bitwiseXorMix(a: Int, b: Int, c: Int): Int {
        return a ^ b & c;
    }

    static function bitwiseXorMix2(a: Int, b: Int, c: Int): Int {
        return a & b ^ c;
    }

    static function bitwiseOrXor(a: Int, b: Int, c: Int): Int {
        return a | b ^ c;
    }

    public static function main(): Void {
        Sys.println(subCompound(10, 3, 2));
        Sys.println(divCompound(100, 7, 5));
        Sys.println(modCompound(20, 3, 4));
        Sys.println(bitwiseMix(0xF0, 0x0F, 0x01));
        Sys.println(bitwiseMix2(0xF0, 0x0F, 0x01));
        Sys.println(bitwiseXorMix(0xF0, 0x0F, 0x33));
        Sys.println(bitwiseXorMix2(0xF0, 0x0F, 0x33));
        Sys.println(bitwiseOrXor(0xF0, 0x0F, 0x33));
    }
}
