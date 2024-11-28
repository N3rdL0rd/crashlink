class Switch {
    static function main() {
        var a = 3;
        var b = switch (a) {
            case 0: a * 2;
            case 3: a - 1;
            default: a << 2;
        }
    }
}