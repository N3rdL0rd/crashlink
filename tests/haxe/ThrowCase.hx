class ThrowCase {
    static function decode(code: Int): String {
        if (code < 0 || code > 0x10FFFF)
            throw "Invalid code point " + code;
        return String.fromCharCode(code);
    }

    public static function main(): Void {
        try {
            var s = decode(65);
        } catch (e: Dynamic) {
            trace(e);
        }
    }
}
