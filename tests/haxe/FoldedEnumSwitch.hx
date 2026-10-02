enum Looping {
    NetscapeLooping(loops:Int);
    Other(data:String);
}

enum Extension {
    Comment(text:String);
    Application(ext:Looping);
}

enum Block {
    Frame(index:Int);
    Ext(ext:Extension);
}

class FoldedEnumSwitch {
    // Same shape as format.gif.Tools.loopCount.
    static function loopCount(blocks:List<Block>):Int {
        for (block in blocks) {
            switch (block) {
                case Ext(Application(NetscapeLooping(loops))):
                    return loops;
                default:
            }
        }
        return 1;
    }

    static function main() {
        var blocks = new List<Block>();
        blocks.add(Frame(0));
        blocks.add(Ext(Comment("x")));
        blocks.add(Ext(Application(NetscapeLooping(3))));
        Sys.println(loopCount(blocks));
    }
}
