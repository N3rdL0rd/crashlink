class TypedCatchRethrow {
    static function main() {
        try {
            throw "deep";
        } catch (e:String) {
            throw e;
        }
    }
}
