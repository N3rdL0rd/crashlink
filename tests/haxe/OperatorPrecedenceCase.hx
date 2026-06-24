class OperatorPrecedenceCase {
    static function combine(a: Int, b: Int): Int {
        return (a >> 2) + b;
    }

    static function maskAdd(a: Int, b: Int): Int {
        return (a & 0xFF) + b;
    }

    public static function main(): Void {
        var x = combine(10, 3);
        var y = maskAdd(10, 3);
    }
}
