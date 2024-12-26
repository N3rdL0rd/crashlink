class If {
    public static function other() {
        trace('hi mom');
    }

    public static function other2() {
        trace('hi dad');
    }

    public static function spacer() {
        trace('spacer');
    }

    static function main() {
        var a = 500;
        var b = 10;
        spacer();
        if (a > b) {
            other();
        } else {
            other2();
        }
        spacer();
        if (a > 400 && a > b) {
            other();
        } else {
            other2();
        }
    }
}
