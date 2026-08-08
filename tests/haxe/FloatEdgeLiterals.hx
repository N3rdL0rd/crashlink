class FloatEdgeLiterals {
    static function main() {
        var maxInt = 0x7FFFFFFF;
        var minInt = -2147483648;
        var maxDouble = 1.7976931348623157e+308;
        var negZero = -0.0;
        var posZero = 0.0;

        trace(maxInt);
        trace(minInt);
        trace(maxDouble);
        trace(negZero);
        trace(negZero == posZero);
        trace(1.0 / negZero);
        trace(1.0 / posZero);
        trace(Std.string(negZero));

        var arr = [maxInt, minInt];
        trace(arr[0] + 1);
        trace(arr[1] - 1);

        var f = -0.0;
        f += 0.0;
        trace(f);
        trace(1.0 / f);
    }
}
