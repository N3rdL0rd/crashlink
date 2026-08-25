class BitwiseEqualPrec {
    static function orOfAnd(a: Int, b: Int, c: Int): Int {
        return a | (b & c); // right-nested: compute b&c first, then a|that
    }

    static function xorOfAnd(a: Int, b: Int, c: Int): Int {
        return a ^ (b & c);
    }

    static function andOfOr(a: Int, b: Int, c: Int): Int {
        return a & (b | c);
    }

    static function andOfXor(a: Int, b: Int, c: Int): Int {
        return a & (b ^ c);
    }

    public static function main(): Void {
        Sys.println(orOfAnd(0xF0, 0x0F, 0x33));
        Sys.println(xorOfAnd(0xF0, 0x0F, 0x33));
        Sys.println(andOfOr(0xF0, 0x0F, 0x33));
        Sys.println(andOfXor(0xF0, 0x0F, 0x33));
    }
}
