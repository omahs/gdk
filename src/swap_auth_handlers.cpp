#include "swap_auth_handlers.hpp"
#include "ga_auth_handlers.hpp"

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    namespace {
        static nlohmann::json get_tx_input_fields(const wally_tx_ptr& tx, size_t index)
        {
            GDK_RUNTIME_ASSERT(index < tx->num_inputs);
            const wally_tx_input* in = tx->inputs + index;
            nlohmann::json::array_t witness;
            for (size_t i = 0; i < in->witness->num_items; ++i) {
                const auto* item = in->witness->items + i;
                witness.push_back(b2h(gsl::make_span(item->witness, item->witness_len)));
            }
            return { { "txhash", b2h_rev(gsl::make_span(in->txhash, sizeof(in->txhash))) }, { "pt_idx", in->index },
                { "sequence", in->sequence }, { "script_sig", b2h(gsl::make_span(in->script, in->script_len)) },
                { "witness", std::move(witness) } };
        }

        static void add_asset_utxos(
            const nlohmann::json& utxos, const std::string& asset_id, nlohmann::json::array_t& used_utxos)
        {
            const auto p = utxos.find(asset_id);
            if (p != utxos.end()) {
                for (const auto& u : *p) {
                    used_utxos.push_back(u); // FIXME: std::move
                }
            }
        }

        static auto liquidex_get_fields(nlohmann::json& in_out)
        {
            nlohmann::json::array_t res;
            res.resize(in_out.size());
            for (size_t i = 0; i < in_out.size(); ++i) {
                res[i]["asset"] = std::move(in_out[i]["asset_id"]);
                res[i]["asset_blinder"] = std::move(in_out[i]["assetblinder"]);
                res[i]["amount"] = std::move(in_out[i]["satoshi"]);
                res[i]["amount_blinder"] = std::move(in_out[i]["amountblinder"]);
            }
            return res;
        }

        static nlohmann::json liquidex_get_maker_input(const wally_tx_ptr& tx, const nlohmann::json& proposal_input)
        {
            auto maker_input = get_tx_input_fields(tx, 0);
            maker_input["asset_id"] = proposal_input.at("asset");
            maker_input["assetblinder"] = proposal_input.at("asset_blinder");
            maker_input["satoshi"] = proposal_input.at("amount");
            maker_input["amountblinder"] = proposal_input.at("amount_blinder");
            maker_input["skip_signing"] = true;
            return maker_input;
        }

        static nlohmann::json liquidex_get_maker_addressee(
            const network_parameters& net_params, const wally_tx_ptr& tx, const nlohmann::json& proposal_output)
        {
            GDK_RUNTIME_ASSERT(tx->num_outputs);
            const auto& tx_output = tx->outputs[0];
            const auto rangeproof = gsl::make_span(tx_output.rangeproof, tx_output.rangeproof_len);
            const auto nonce = gsl::make_span(tx_output.nonce, tx_output.nonce_len);
            const auto scriptpubkey = gsl::make_span(tx_output.script, tx_output.script_len);

            nlohmann::json ret = { { "address", get_address_from_scriptpubkey(net_params, scriptpubkey) },
                { "is_blinded", true }, { "index", 0 }, { "nonce_commitment", b2h(nonce) },
                { "range_proof", b2h(rangeproof) }, { "asset_id", proposal_output.at("asset") },
                { "assetblinder", proposal_output.at("asset_blinder") }, { "satoshi", proposal_output.at("amount") },
                { "amountblinder", proposal_output.at("amount_blinder") } };
            if (proposal_output.contains("blinding_nonce")) {
                ret["blinding_nonce"] = proposal_output["blinding_nonce"];
            }
            return ret;
        }
    } // namespace

    //
    // Create swap transaction
    //
    create_swap_transaction_call::create_swap_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_swap_transaction")
        , m_details(details)
        , m_swap_type(json_get_value(m_details, "swap_type"))
        , m_is_signed(false)
    {
    }

    auth_handler::state_type create_swap_transaction_call::call_impl()
    {
        if (m_swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "output_type") == "liquidex_v0", "unknown output_type");
            return liquidex_impl();
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");
        }
        return state_type::error; // Unreachable
    }

    auth_handler::state_type create_swap_transaction_call::liquidex_impl()
    {
        // TODO: We may wish to allow receiving to a different subaccount.
        //       For now, receive to the same subaccount we are sending from
        const uint32_t subaccount = m_details.at("send").at("subaccount");

        if (m_receive_address.empty()) {
            // Fetch a new address to receive the swapped asset on
            // TODO: Further validate the inputs
            const nlohmann::json addr_details = { { "subaccount", subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, addr_details));
            return state_type::make_call;
        }
        if (m_create_details.empty()) {
            // Call create_transaction to create the swap tx
            nlohmann::json addressee = { { "address", m_receive_address.at("address") } };
            addressee.update(m_details.at("receive"));
            std::vector<nlohmann::json> addressees{ std::move(addressee) };
            auto send = m_details.at("send");
            std::vector<nlohmann::json> utxos{ { send.at("asset_id"), send } };
            std::vector<nlohmann::json> used_utxos{ std::move(send) };
            nlohmann::json create_details
                = { { "addressees", std::move(addressees) }, { "subaccount", subaccount }, { "is_partial", true },
                      { "utxo_strategy", "manual" }, { "utxos", utxos }, { "used_utxos", std::move(used_utxos) } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
            return state_type::make_call;
        }
        // Call sign_transaction to sign the callers side
        constexpr uint32_t sighash = WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY;
        m_create_details.at("used_utxos").at(0)["user_sighash"] = sighash;
        nlohmann::json::array_t sign_with = { "user" };
        if (m_create_details.at("subaccount_type") != "2of2_no_recovery") {
            sign_with.emplace_back("green-backend");
        }
        m_create_details["sign_with"] = std::move(sign_with);
        add_next_handler(new sign_transaction_call(m_session_parent, m_create_details));
        return state_type::done; // We are complete once tx signing is done
    }

    void create_swap_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        if (m_receive_address.empty()) {
            // Call result is our new receive address
            m_receive_address = std::move(next_handler->move_result());
        } else if (m_create_details.empty()) {
            // Call result is our created tx
            m_create_details = std::move(next_handler->move_result());
        } else if (!m_is_signed) {
            // Call result is our signed tx
            auto result = std::move(next_handler->move_result());
            // Create liquidex_v0 proposal to return
            auto& tx_inputs = result.at("used_utxos");
            auto& tx_outputs = result.at("transaction_outputs");
            nlohmann::json::array_t inputs = liquidex_get_fields(tx_inputs);
            nlohmann::json::array_t outputs = liquidex_get_fields(tx_outputs);
            m_result = nlohmann::json({ { "version", 0 }, { "transaction", std::move(result["transaction"]) },
                { "inputs", std::move(inputs) }, { "outputs", std::move(outputs) } });
            if (m_create_details.at("subaccount_type") == "2of2_no_recovery") {
                m_result["inputs"][0]["script"] = std::move(tx_inputs.at(0).at("prevout_script"));
                m_result["outputs"][0]["blinding_nonce"] = std::move(tx_outputs.at(0).at("blinding_nonce"));
            }
            m_is_signed = true;
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown next handler called");
        }
    }

    //
    // Complete swap transaction
    //
    complete_swap_transaction_call::complete_swap_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "complete_swap_transaction")
        , m_details(details)
        , m_swap_type(json_get_value(m_details, "swap_type"))
    {
    }

    auth_handler::state_type complete_swap_transaction_call::call_impl()
    {
        if (m_swap_type == "liquidex") {
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "input_type") == "liquidex_v0", "unknown input_type");
            GDK_RUNTIME_ASSERT_MSG(json_get_value(m_details, "output_type") == "transaction", "unknown output_type");
            GDK_RUNTIME_ASSERT(m_net_params.is_liquid());
            return liquidex_impl();
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "unknown swap_type");
        }
        return state_type::error; // Unreachable
    }

    auth_handler::state_type complete_swap_transaction_call::liquidex_impl()
    {
        // FIXME: Add validation
        const auto& proposal = m_details.at("proposal");
        const uint32_t subaccount = m_details.at("subaccount"); // TODO: get from first utxo?

        if (m_receive_address.empty()) {
            // Fetch a new address to receive the swapped asset on
            // TODO: Further validate the inputs
            const nlohmann::json addr_details = { { "subaccount", subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, addr_details));
            return state_type::make_call;
        } else if (m_create_details.empty()) {
            const bool is_liquid = true;
            const auto& proposal_input = proposal.at("inputs").at(0);
            const auto maker_asset_id = proposal_input.at("asset");
            const auto& proposal_output = proposal.at("outputs").at(0);
            const auto taker_asset_id = proposal_output.at("asset");
            const auto& utxos = m_details.at("utxos");
            const wally_tx_ptr tx = tx_from_hex(proposal.at("transaction"), tx_flags(is_liquid));

            // Get the input UTXOs
            auto maker_input = liquidex_get_maker_input(tx, proposal_input);
            nlohmann::json::array_t used_utxos = { std::move(maker_input) };
            std::set<std::string> asset_ids{ maker_asset_id, taker_asset_id, m_net_params.policy_asset() };
            for (const auto& asset_id : asset_ids) {
                add_asset_utxos(utxos, asset_id, used_utxos);
            }

            auto maker_addressee = liquidex_get_maker_addressee(m_net_params, tx, proposal_output);
            nlohmann::json taker_addressee = { { "address", m_receive_address.at("address") },
                { "asset_id", maker_asset_id }, // Taker is receiving the makers asset
                { "satoshi", proposal_input.at("amount") } };
            nlohmann::json::array_t addressees = { std::move(maker_addressee), std::move(taker_addressee) };

            nlohmann::json create_details = { { "subaccount", subaccount }, { "addressees", std::move(addressees) },
                { "transaction_version", tx->version }, { "transaction_locktime", tx->locktime },
                { "utxo_strategy", "manual" }, { "utxos", nlohmann::json::object() },
                { "used_utxos", std::move(used_utxos) }, { "randomize_inputs", false } };
            add_next_handler(new create_transaction_call(m_session_parent, create_details));
            return state_type::make_call;
        }
        return state_type::done;
    }

    void complete_swap_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        if (m_receive_address.empty()) {
            // Call result is our new receive address
            m_receive_address = std::move(next_handler->move_result());
        } else if (m_create_details.empty()) {
            // Call result is our created tx
            m_create_details = std::move(next_handler->move_result());
            m_result = m_create_details; // FIXME: set directly if not signing
        } else {
            // FIXME: sign?
        }
    }
} // namespace sdk
} // namespace ga
