class TernaryNullCoalesce {
    static function max(a: Int, b: Int): Int {
        return a > b ? a : b;
    }

    static function sign(x: Int): Int {
        return x > 0 ? 1 : (x < 0 ? -1 : 0);
    }

    static function isCJK(code: Int): Bool {
        if (code >= 0x2E80 && code <= 0xA4CF) {
            return true;
        }
        if (code >= 0xF900) {
            return code <= 0xFAFF;
        }
        return false;
    }

    static function nullDefault(v: Null<Int>): Int {
        return v ?? 42;
    }

    static function boolAssign(c: Bool): Int {
        var x = c ? 10 : 20;
        return x;
    }

    static function main() {
        Sys.println(max(3, 7));
        Sys.println(max(9, 2));
        Sys.println(sign(-5));
        Sys.println(sign(0));
        Sys.println(sign(11));
        Sys.println(isCJK(0x3000));
        Sys.println(isCJK(0xF950));
        Sys.println(isCJK(0x1000));
        Sys.println(nullDefault(null));
        Sys.println(nullDefault(5));
        Sys.println(boolAssign(true));
        Sys.println(boolAssign(false));
    }
}
