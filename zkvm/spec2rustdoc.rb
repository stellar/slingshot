#!/usr/bin/env ruby
# Copies the instructions spec as documentation for `ops::Instruction` enum variants.

ops_rs_filepath = "src/ops.rs"
spec_md = File.read("docs/zkvm-spec.md")
ops_rs = File.read(ops_rs_filepath)

ops = ops_rs.match(%r{pub enum Instruction\s*\{(.*?)Ext\(u8\)}m)[1].
     gsub(%r{//[^\n]*}m, "").
     gsub(%r{\n\s*\n},"\n").
     strip.
     split("\n").
     map { |line| 
        opline = line.strip
        op = opline.
                gsub(%r{^\s*},"").
                gsub(%r{,$},"").
                gsub(%r{\(.*?\),?},"").
                downcase
        [opline,op]
     }

documented_ops = ops.map {|(opline, op)|
    spec = spec_md.match(%r{#### #{op}(.*?)\n###}m)[1].
        gsub(%r{\[`([^\]]+?)`\]\([^\)]+\)}, "`\\1`"). # change links over code to code
        gsub(%r{\[([^\]]+?)\]\([^\)]+\)}, "_\\1_"). # change links to emphasis
        gsub(%r{```\s*\n(.*?)```}m, "```ascii\n\\1```").
        gsub(%r{\[([^\]]{1,3})\]}, "(\\1)").
        strip.
        split("\n").
        map{|docline| "    " + "/// #{docline}".strip }
        .join("\n") + "\n"
    [opline, spec]
}.
map{|(opline,spec)| 
    spec + "    " + opline + "\n" 
}

new_code = ops_rs.gsub(%r{(pub enum Instruction\s*\{\s*\n)(.*?)(\n\s*Ext\(u8\))}m) do |_|
    m = Regexp.last_match
    m[1] + 
    documented_ops.join("\n") +
    "\n    /// Unassigned opcode." +
    m[3]
end

File.open(ops_rs_filepath, "w"){|f| f.write(new_code) }
