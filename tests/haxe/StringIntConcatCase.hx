class StringIntConcatCase {
    static function decode(code: Int): String {
        if (code >= 0) {
            if (code < 100) {
                return String.fromCharCode(code);
            }
        }
        throw "Invalid code " + code;
    }
    static function main() {
        trace(decode(5));
        trace(decode(200));
    }
}
