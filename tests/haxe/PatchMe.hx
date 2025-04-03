class PatchMe {
    static function main() {
        var val = 1.0;
        var val2 = 2.0;
        thing(val, val2);
    }

    static function thing(val: Float, val2: Float) {
        if (val == 2.0) {
            trace("Success!");
        } else {
            trace("Patch failed!");
        }
    }
}