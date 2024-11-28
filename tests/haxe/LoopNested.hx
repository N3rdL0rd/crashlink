class LoopNested {
    static function main() {
        var b = 69;
        while (true) {
            b *= 2;
            if (b > 1000) {
                break;
            }
            var a = 0;
            if (a > 1) {
                a = 1;
            } else {
                a = 2;
                return;
            }
            while (true) {
                b *= 2;
                if (b > 1000) {
                    break;
                }
            }
        }
    }
}