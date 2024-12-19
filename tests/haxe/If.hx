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
        if (a > 400) {
            
        }
        spacer();
        var b = 10;
        if (a > b) {
            
        }
        spacer();
        if (a > 400) {
            
        } else {
            
        }
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
