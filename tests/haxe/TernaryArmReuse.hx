class TernaryArmReuse {
    static function f(x: Int, y: Int): Int {
        var v = x > 0 ? (x * 2 + 1) : (y * 3 - 1);
        return v + (x > 0 ? (x - y) : (y - x));
    }

    static function main() {
        trace(f(5, 2));
        trace(f(-5, 2));
        trace(f(0, 0));
        trace(f(3, 3));
    }
}
