class BitwiseShiftOps {
    static function main() {
        var a: Int = -8;
        trace(a >> 1);
        trace(a >>> 1);
        trace(a << 2);
        var b: Int = -1;
        trace(b >>> 28);
        var c: Int = 0xFFFFFFFF;
        trace(c);
        trace(c & 0xFF);
        trace(~a);
    }
}
