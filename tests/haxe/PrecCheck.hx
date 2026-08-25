class PrecCheck {
    static function main() {
        var a = 5, b = 3, c = 2, d = 7;
        Sys.println(a | b & c ^ d);
        Sys.println((a << 2) + (b >> 1));
        Sys.println(a + b << 2);
        Sys.println(a << b + 2);
        Sys.println(a - b << 1);
        Sys.println(1 == 2 != (3 == 3));
        Sys.println(a < b == (c < d));
    }
}
