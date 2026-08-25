class SwitchRegisterReuse {
    static function pick(x: Int): Int {
        var result: Int;
        switch (x) {
            case 0:
                var a = x + 1;
                result = a * 2;
            case 1:
                var b = x * 100;
                result = b + 5;
            default:
                var c = x - 1;
                result = c * c;
        }
        return result;
    }

    static function main() {
        trace(pick(0));
        trace(pick(1));
        trace(pick(2));
        trace(pick(-3));
    }
}
