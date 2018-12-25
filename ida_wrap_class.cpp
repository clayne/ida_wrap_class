#include "stdafx.h"

extern plugin_t PLUGIN;

// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;

static bool inited = false;

int create_open_file(const char* file_name) {
	int file_id = qopen(file_name, O_BINARY | O_TRUNC | O_CREAT);
	if (file_id == BADADDR)
		file_id = qcreate(file_name, 511);

	return file_id;
}

struct generate_cpp_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx)
  {
    vdui_t &vu = *get_widget_vdui(ctx->widget);
	cfuncptr_t pfunc = vu.cfunc;

	if (pfunc != NULL)
	{
		qstring method_filter_name = "";
		flags_t method_flags = get_flags(pfunc->entry_ea);
		if (is_func(method_flags))
		{
			method_filter_name = get_short_name(pfunc->entry_ea);
			size_t pos_ag = method_filter_name.find("::");
			if (pos_ag > 0)
			{
				method_filter_name.remove(pos_ag, method_filter_name.size() - pos_ag);

				//!--Write file
				qstring classnamefile = method_filter_name;
				classnamefile.replace("<", "_");
				classnamefile.replace(">", "_");
				classnamefile += ".hpp";
				int file_id = create_open_file(classnamefile.c_str());
				if (file_id != -1)
				{
					qstring header = "class ";
					header += method_filter_name;
					header += "\r\n { \r\n\r\n ";
					qwrite(file_id, header.c_str(), header.length());

					size_t total_func_qty = get_func_qty();
					qstring dump_line = "";
					method_filter_name += "::";
					for (size_t i = 0; i < total_func_qty; i++)
					{
						dump_line = "inline \r\n";
						func_t *function = getn_func(i);
						if (function != NULL)
						{
							qstring dfuncname = get_short_name(function->start_ea);
							if (dfuncname.find(method_filter_name) == 0)
							{
								//!--same class
								hexrays_failure_t hf;
								cfuncptr_t cfunc = decompile(function, &hf);
								if (cfunc != NULL)
								{
									tinfo_t type;
									cfunc->get_func_type(&type);

									//!--ret type
									qstring rettype_str = "";
									tinfo_t ret_type = type.get_rettype();
									ret_type.print(&rettype_str, NULL, PRTYPE_DEF | PRTYPE_1LINE | PRTYPE_CPP);

									//!--calling conversion
									bool is_thiscall = false;
									qstring cc_str = "";
									cm_t cc_type = type.get_cc();
									switch (cc_type)
									{
									case CM_CC_CDECL:
									{
										cc_str = "__cdecl";
										break;
									}
									case CM_CC_STDCALL:
									{
										cc_str = "__stdcall";
										break;
									}
									case CM_CC_FASTCALL:
									{
										cc_str = "__fastcall";
										break;
									}
									case CM_CC_THISCALL:
									{
										cc_str = "__thiscall";
										is_thiscall = true;
										break;
									}
									}

									size_t pos_ag2 = method_filter_name.find("::");
									if (pos_ag2 > 0)
									{
										dfuncname.remove(0, pos_ag2 + 2);
									}

									dfuncname.replace("::", "_");

									dfuncname.replace("`vector deleting destructor'", "vec_del");
									size_t pos_ag = dfuncname.find("(");
									if (pos_ag > 0)
									{
										dfuncname.remove(pos_ag, dfuncname.size() - pos_ag);
									}

									if (rettype_str.size() > 0)
									{
										dump_line += rettype_str;
									}
									if (cc_str.size() > 0)
									{
										dump_line += " ";
										dump_line += cc_str;
									}
									if (dfuncname.size() > 0)
									{
										dump_line += " ";
										dump_line += dfuncname;
									}

									qstring args_str;
									qstring args_type_str;
									qstring args_val_str;
									if (type.get_nargs() > 0)
									{
										int vidx = 0;
										args_str += "(";
										args_type_str += "(";
										args_val_str += "(";
										if (is_thiscall == true)
										{
											args_type_str += "void *";
											args_val_str += "(void*)this";
											vidx = 1;
										}
										lvars_t* lvars = cfunc->get_lvars();
										for (int lvi = 0; lvi < lvars->size(); ++lvi)
										{
											lvar_t lv = lvars->at(lvi);
											if (lv.is_arg_var())
											{
												if (is_thiscall == true && vidx == 1)
												{
													vidx++;
													continue;
												}

												qstring v_str = "";
												qstring vname_str = "";
												tinfo_t v_type = lv.type();
												vname_str = lv.name;
												v_type.print(&v_str, NULL, PRTYPE_1LINE | PRTYPE_CPP);
												if (v_str.size() > 0)
												{
													if ((is_thiscall == false && vidx > 0) || (is_thiscall == true && vidx > 1))
													{
														args_str += ",";
														args_type_str += ",";
														args_val_str += ",";
													}

													args_str += " ";
													args_str += v_str;
													args_type_str += v_str;
													if (vname_str.size() > 0)
													{
														args_str += " ";
														args_str += vname_str;
														args_val_str += vname_str;
													}
												}
												vidx++;
											}
										}

										args_str += ")";
										args_type_str += ")";
										args_val_str += ")";
									}
									else
									{
										args_str += "()";
										args_type_str += "()";
										args_val_str += "()";
									}
									dump_line += args_str;
									dump_line += "\r\n{\r\n";
									if (!ret_type.is_decl_void())
									{
										dump_line += "\t\t return ((";
									}
									else
									{
										dump_line += "\t\t((";
									}
									dump_line += rettype_str;
									dump_line += "(";
									dump_line += cc_str;
									dump_line += "*)";
									dump_line += args_type_str;
									dump_line += ")";
									dump_line += "((DWORD)";
									dump_line.cat_sprnt("0x%08X", function->start_ea);
									dump_line += "))";
									dump_line += args_val_str;
									dump_line += "";
									dump_line += ";\r\n}\r\n";
									dump_line += "\n";
									qwrite(file_id, dump_line.c_str(), dump_line.length());
								}
							}
						}
					}

					qstring endc = "}; \r\n";
					qwrite(file_id, endc.c_str(), endc.length());
					qclose(file_id);
				}//file id
			}
			else
			{
				msg("Function name not like 'Class_Abc::FunctionA'");
			}
		}
	}

	info("Generated class method.");
    return 1;
  }

	virtual action_state_t idaapi update(action_update_ctx_t *ctx)
	{
		bool ok = ctx->widget_type == BWN_DISASM;
		return ok ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
	}
};

static generate_cpp_t generate_cpp_ah;
static const action_desc_t wrap_action =
  ACTION_DESC_LITERAL(
   "IDAWRAP:WRAP",
    "Generate all method in same class",
    &generate_cpp_ah,
    NULL,
    NULL,
    -1
  );

//--------------------------------------------------------------------------
static int idaapi callback(void *, hexrays_event_t event, va_list va)
{
	switch (event)
	{
	case hxe_right_click:
	{
		TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *popup = va_arg(va, TPopupMenu *);
		vdui_t &vu = *va_arg(va, vdui_t *);
		//add_custom_viewer_popup_item(vu.ct, "Generate all method in same class", "", generate_cpp, &vu);
		attach_action_to_popup(widget, popup, "IDAWRAP:WRAP");
	}
	break;
	default:
		break;
	}
	return 0;
}


int idaapi init(void)
{
	if (!init_hexrays_plugin())
		return PLUGIN_SKIP; // no decompiler

	bool dump_types = false,
		dump_ctrees = false;
	qstring crypto_prefix;

	qstring options = get_plugin_options(PLUGIN.wanted_name);

	install_hexrays_callback(callback, NULL);
	const char *hxver = get_hexrays_version();
	register_action(wrap_action);
	inited = true;

	static const char hotkey_vc[] = "V";
	static int hotcode_vc;

	return PLUGIN_KEEP;
}


//--------------------------------------------------------------------------
void idaapi term(void)
{
	if (inited)
	{
		remove_hexrays_callback(callback, NULL);
		term_hexrays_plugin();
	}
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{

}

//--------------------------------------------------------------------------
static char comment[] = "Wrap class into c code.";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE,
	init,
	term,
	run,
	comment,
	"",
	"Wrap class",
	""
};

