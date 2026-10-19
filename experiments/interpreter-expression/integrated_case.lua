local function add_five(value)
    return value + 5
end

local function branch_call(value)
    if value == 0 then
        return add_five(5)
    end
    return add_five(value)
end

local function append_five(value)
    return value .. "5"
end

if case_mode == 0 then
    return branch_call(case_number)
end
return append_five(case_text)
