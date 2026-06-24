class ParamRenameCase {
    static function absDouble(x: Int): Int {
        if (x < 0)
            x = -x;
        return x * 2;
    }

    public static function main(): Void {
        var r = absDouble(-5);
    }
}
