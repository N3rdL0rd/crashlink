class PatchMe {
    static function main() {
        var val = 1.0;
        thing(val);
    }

    static function thing(val: Float) {
        if (val == 2.0) {
            trace("Success!");
        } else {
            trace("Patch failed!");
        }
    }
}